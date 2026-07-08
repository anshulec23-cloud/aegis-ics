# Live Trust Scoring Algorithm

The live trust score ($T_{\text{final}}$) of a device evaluates telemetry integrity and flags anomalous behavior. It is computed as a weighted combination of machine learning outputs, cryptographic signatures, historical deviation, and rolling stability metrics.

## Formula & Weighting

Under normal conditions, the base trust score is defined as:

$$T_{\text{score}} = 0.35 \cdot (1.0 - S_{\text{anomaly}}) + 0.30 \cdot S_{\text{signature}} + 0.20 \cdot S_{\text{history}} + 0.15 \cdot S_{\text{stability}}$$

Where:

1. **Anomaly Frequency ($S_{\text{anomaly}}$)**: Sourced from the Random Forest ML classifier probability ($P(\text{anomaly})$). High anomaly probabilities reduce the overall trust score.
2. **Signature Validity ($S_{\text{signature}}$)**: Cryptographic verification of the HMAC-SHA256 telemetry signature. Asserts $1.0$ if the signature is valid, $0.0$ if invalid or missing.
3. **Historical Deviation ($S_{\text{history}}$)**: Measures how far current readings deviate from the rolling average of the last 10 telemetry points.
   $$S_{\text{history}} = 1.0 - \text{min}\left(1.0, \frac{\Delta\text{Temp}}{25.0} + \frac{\Delta\text{Pressure}}{5.0}\right)$$
4. **Sensor Stability ($S_{\text{stability}}$)**: Evaluates sensor signal variance over the rolling history window. Low variance matches high stability ($1.0$), while high jitter/fluctuation reduces the score towards $0.0$.

---

## Low-Confidence Fallback Logic

If the Random Forest classifier model confidence is low ($C < 0.50$), the system blends the trust score with a deterministic, rule-based fallback score ($S_{\text{fallback}}$) to avoid false classification:

$$T_{\text{final}} = \frac{T_{\text{score}} + S_{\text{fallback}}}{2.0}$$

Where the fallback score $S_{\text{fallback}}$ is computed by subtracting set penalties for out-of-bound variables:
- **Temperature out of bounds ($<0^\circ\text{C}$ or $>50^\circ\text{C}$)**: $-0.35$ penalty
- **Pressure out of bounds ($<0\text{ bar}$ or $>8\text{ bar}$)**: $-0.25$ penalty
- **Invalid HMAC Signature**: $-0.40$ penalty

If $T_{\text{final}} < 0.40$, the microsegmentation engine is triggered automatically to isolate the target device.
