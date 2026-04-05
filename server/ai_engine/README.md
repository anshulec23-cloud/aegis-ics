# AI Engine

This is the scoring logic for the demo. It turns telemetry into a trust score from 0.0 to 1.0.

## Files
- `__init__.py` - marks `server.ai_engine` as a Python package.
- `engine.py` - main trust engine and decision logic.
- `rf_model.py` - loads and runs the Random Forest model.
- `parameters.py` - calculates the trust-score inputs.
- `microseg.py` - stores isolated devices.
- `rule_fallback.py` - backup scoring when the model is missing or unsure.
- `model/` - place the trained model file here.

## How It Works
The engine combines model output, signature validity, time history, and sensor stability into one trust score. Low scores trigger isolation.
