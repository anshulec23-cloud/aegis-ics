"""
neural_policy.py - Physics-Informed Neural Safety Policy Network (NSPN)
========================================================================
Implements a deep neural safety interlock network to evaluate SCADA setpoint
commands against non-linear multi-variable cyber-physical hazard envelopes.

Operates 100% locally and offline. Features a dual-execution inference engine:
1. Native PyTorch execution when PyTorch is present.
2. Zero-overhead vectorized NumPy forward pass with identical weights,
   guaranteeing instant startup and zero external DLL failure modes inside
   frozen PyInstaller executables (Windows .exe & Linux ELF).
"""

import os
import sys
import math
import numpy as np
from typing import Tuple, Dict, Any, Optional

# Attempt to import PyTorch; if not present, vectorized NumPy engine is used
try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    torch = None
    nn = None
    TORCH_AVAILABLE = False


def _get_resource_path(relative_path: str) -> str:
    """Resolve file path for normal runtime and frozen PyInstaller executables."""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    target = os.path.join(base_path, relative_path)
    if not os.path.exists(target):
        alt = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", relative_path)
        if os.path.exists(alt):
            return alt
    return target


if TORCH_AVAILABLE:
    class NeuralSafetyPolicyTorch(nn.Module):
        """Deep Multi-Layer Perceptron for Cyber-Physical Safety Invariant Evaluation."""
        def __init__(self, in_features: int = 6, hidden_dims: tuple = (64, 32, 16)):
            super().__init__()
            self.network = nn.Sequential(
                nn.Linear(in_features, hidden_dims[0]),
                nn.LeakyReLU(0.1),
                nn.Linear(hidden_dims[0], hidden_dims[1]),
                nn.LeakyReLU(0.1),
                nn.Linear(hidden_dims[1], hidden_dims[2]),
                nn.LeakyReLU(0.1),
                nn.Linear(hidden_dims[2], 1),
                nn.Sigmoid()
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            return self.network(x)
else:
    NeuralSafetyPolicyTorch = None


class NeuralSafetyPolicy:
    """
    Local Neural Safety Policy Network (NSPN).
    Evaluates state-action tuples:
        z = [T_live, P_live, Vib_live, RPM_live, Curr_live, Setpoint_Val]
    Outputs P(Safe | s, u) in [0.0, 1.0].
    """
    def __init__(self, weights_path: Optional[str] = None):
        self.weights_loaded = False
        self.torch_model = None
        self.weights_dict = {}
        self.input_means = np.array([32.0, 4.0, 1.5, 1200.0, 5.0, 25.0], dtype=np.float32)
        self.input_stds = np.array([12.0, 2.5, 1.2, 900.0, 2.0, 20.0], dtype=np.float32)

        # Candidate paths for weights
        model_dir = _get_resource_path("model")

        if weights_path:
            # Explicit path provided by caller
            if os.path.exists(weights_path):
                if weights_path.endswith(".npz"):
                    try:
                        data = np.load(weights_path, allow_pickle=False)
                        self.weights_dict = {k: data[k] for k in data.files if k not in ("means", "stds")}
                        if "means" in data.files:
                            self.input_means = data["means"]
                        if "stds" in data.files:
                            self.input_stds = data["stds"]
                        self.weights_loaded = True
                    except Exception as e:
                        print(f"[NeuralPolicy] Warning: Could not load explicit .npz weights ({e})")
                elif weights_path.endswith(".pt") and TORCH_AVAILABLE:
                    try:
                        checkpoint = torch.load(weights_path, map_location="cpu", weights_only=True)
                        self.torch_model = NeuralSafetyPolicyTorch()
                        if isinstance(checkpoint, dict) and "state_dict" in checkpoint:
                            self.torch_model.load_state_dict(checkpoint["state_dict"])
                            if "means" in checkpoint:
                                self.input_means = np.array(checkpoint["means"], dtype=np.float32)
                            if "stds" in checkpoint:
                                self.input_stds = np.array(checkpoint["stds"], dtype=np.float32)
                        else:
                            self.torch_model.load_state_dict(checkpoint)
                        self.torch_model.eval()
                        self.weights_loaded = True
                    except Exception as e:
                        import pickle
                        if isinstance(e, (pickle.UnpicklingError, RuntimeError)):
                            print(f"[NeuralPolicy] Warning: Legacy model format detected. Cannot load with weights_only=True. ({e})")
                        else:
                            print(f"[NeuralPolicy] Warning: Could not load explicit PyTorch model ({e})")
        else:
            # Default auto-discovery in model directory
            npz_path = os.path.join(model_dir, "neural_safety_policy.npz")
            pt_path = os.path.join(model_dir, "neural_safety_policy.pt")

            # 1. Try loading NumPy weights first for universal, ultra-fast inference
            if os.path.exists(npz_path):
                try:
                    data = np.load(npz_path, allow_pickle=False)
                    self.weights_dict = {k: data[k] for k in data.files if k not in ("means", "stds")}
                    if "means" in data.files:
                        self.input_means = data["means"]
                    if "stds" in data.files:
                        self.input_stds = data["stds"]
                    self.weights_loaded = True
                except Exception as e:
                    print(f"[NeuralPolicy] Warning: Could not load .npz weights ({e})")

            # 2. Fallback to PyTorch weights if available and NumPy not loaded
            if not self.weights_loaded and TORCH_AVAILABLE and os.path.exists(pt_path):
                try:
                    checkpoint = torch.load(pt_path, map_location="cpu", weights_only=True)
                    self.torch_model = NeuralSafetyPolicyTorch()
                    if isinstance(checkpoint, dict) and "state_dict" in checkpoint:
                        self.torch_model.load_state_dict(checkpoint["state_dict"])
                        if "means" in checkpoint:
                            self.input_means = np.array(checkpoint["means"], dtype=np.float32)
                        if "stds" in checkpoint:
                            self.input_stds = np.array(checkpoint["stds"], dtype=np.float32)
                    else:
                        self.torch_model.load_state_dict(checkpoint)
                    self.torch_model.eval()
                    self.weights_loaded = True
                except Exception as e:
                    import pickle
                    if isinstance(e, (pickle.UnpicklingError, RuntimeError)):
                        print(f"[NeuralPolicy] Warning: Legacy model format detected. Cannot load with weights_only=True. ({e})")
                    else:
                        print(f"[NeuralPolicy] Warning: Could not load PyTorch model ({e})")

    def _normalize(self, x: np.ndarray) -> np.ndarray:
        stds = np.where(self.input_stds < 1e-6, 1.0, self.input_stds)
        return (x - self.input_means) / stds

    def _forward_numpy(self, x: np.ndarray) -> float:
        """Fast vectorized CPU forward pass with LeakyReLU and Sigmoid."""
        h = self._normalize(x)
        w0 = self.weights_dict["w0"]
        b0 = self.weights_dict["b0"]
        h = np.dot(h, w0) + b0
        h = np.where(h > 0, h, h * 0.1)

        w1 = self.weights_dict["w1"]
        b1 = self.weights_dict["b1"]
        h = np.dot(h, w1) + b1
        h = np.where(h > 0, h, h * 0.1)

        w2 = self.weights_dict["w2"]
        b2 = self.weights_dict["b2"]
        h = np.dot(h, w2) + b2
        h = np.where(h > 0, h, h * 0.1)

        w3 = self.weights_dict["w3"]
        b3 = self.weights_dict["b3"]
        out = np.dot(h, w3) + b3
        prob = 1.0 / (1.0 + np.exp(-np.clip(out, -25.0, 25.0)))
        return float(prob.flatten()[0])

    def _forward_torch(self, x: np.ndarray) -> float:
        """Native PyTorch CPU forward pass."""
        with torch.no_grad():
            h = self._normalize(x)
            tensor_x = torch.from_numpy(h.astype(np.float32)).unsqueeze(0)
            prob = self.torch_model(tensor_x).item()
            return float(prob)

    def predict_safety_probability(self, feature_vector: np.ndarray) -> float:
        """
        Calculates P(Safe) for a given 6D input vector:
        [temp, pressure, vibration, hall_effect, current, setpoint_value]
        """
        if not self.weights_loaded:
            # Deterministic heuristic fallback when weights are uninitialized
            t_val, p_val, v_val, r_val, c_val, u_val = feature_vector
            if t_val >= 45.0 and p_val >= 6.0:
                return 0.05
            if u_val >= 50.0 and p_val >= 6.0:
                return 0.08
            if u_val >= 6.5 and t_val >= 45.0:
                return 0.08
            return 0.95

        vec = np.asarray(feature_vector, dtype=np.float32).flatten()
        if len(self.weights_dict) >= 8:
            return self._forward_numpy(vec)
        elif self.torch_model is not None:
            return self._forward_torch(vec)
        return 0.95

    def evaluate_safety(
        self,
        telemetry: Optional[Dict[str, Any]],
        cmd_type: str,
        setpoint_val: float,
        device_id: Optional[str] = None
    ) -> Tuple[bool, float, str]:
        """
        Evaluates a proposed SCADA setpoint against live multi-sensor physical telemetry.
        Returns:
            (is_safe: bool, safety_probability: float, diagnostic_message: str)
        """
        if not telemetry:
            # No live telemetry available; allow deterministic outer boundary check
            return True, 1.0, "Approved (No live telemetry constraints active)"

        temp = float(telemetry.get("temperature", 25.0) or 25.0)
        pres = float(telemetry.get("pressure", 3.0) or 3.0)
        vib = float(telemetry.get("vibration", 1.0) or 1.0)
        hall = float(telemetry.get("hall_effect", 0.0) or 0.0)
        curr = float(telemetry.get("current", 4.0) or 4.0)

        # Synthesize state-action evaluation vector
        vec = np.array([temp, pres, vib, hall, curr, float(setpoint_val)], dtype=np.float32)
        safety_prob = self.predict_safety_probability(vec)

        dev_label = f" on {device_id}" if device_id else ""

        # Hard physics-informed invariant overrides
        if cmd_type == "set_temp" and setpoint_val >= 45.0 and pres >= 6.0:
            safety_prob = min(safety_prob, 0.08)
        if cmd_type == "set_pressure" and setpoint_val >= 6.0 and temp >= 45.0:
            safety_prob = min(safety_prob, 0.08)

        SAFETY_THRESHOLD = 0.50

        if safety_prob < SAFETY_THRESHOLD:
            # Generate explainable AI diagnostic
            if cmd_type == "set_temp" and pres >= 5.5:
                diag = (
                    f"SAFETY INTERLOCK BLOCK (Stuxnet Prevention & Neural Safety Policy): "
                    f"Blocked raising Temperature to {setpoint_val}°C{dev_label} because live Pressure is {pres:.2f} bar. "
                    f"Neural Safety Barrier predicted high-risk thermodynamic failure envelope "
                    f"(P(safe) = {safety_prob * 100:.1f}% < 50.0%). Coordinated high-temperature/high-pressure damage profile detected."
                )
            elif cmd_type == "set_pressure" and temp >= 42.0:
                diag = (
                    f"SAFETY INTERLOCK BLOCK (Stuxnet Prevention & Neural Safety Policy): "
                    f"Blocked raising Pressure to {setpoint_val} bar{dev_label} because live Temperature is {temp:.2f}°C. "
                    f"Neural Safety Barrier predicted high-risk thermodynamic failure envelope "
                    f"(P(safe) = {safety_prob * 100:.1f}% < 50.0%). Coordinated high-temperature/high-pressure damage profile detected."
                )
            else:
                diag = (
                    f"SAFETY INTERLOCK BLOCK (Stuxnet Prevention & Neural Safety Policy): "
                    f"Set {cmd_type} to {setpoint_val}{dev_label} rejected by Neural Safety Policy. "
                    f"Predicted process instability (Safety Confidence: {safety_prob * 100:.1f}%)."
                )
            return False, safety_prob, diag

        return True, safety_prob, f"Approved by Neural Safety Policy (P(safe) = {safety_prob * 100:.1f}%)"


# Global singleton instance for high-efficiency in-process reuse
_global_neural_policy: Optional[NeuralSafetyPolicy] = None

def get_neural_policy() -> NeuralSafetyPolicy:
    global _global_neural_policy
    if _global_neural_policy is None:
        _global_neural_policy = NeuralSafetyPolicy()
    return _global_neural_policy
