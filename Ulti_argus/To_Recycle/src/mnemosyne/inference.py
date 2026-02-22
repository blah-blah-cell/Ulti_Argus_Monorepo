import torch
import numpy as np
import os
import sys

# Ensure proper import path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))
from src.mnemosyne.model import create_model

class InferenceEngine:
    def __init__(self, model_path="d:/Argus_AI/models/payload_classifier.pth"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = create_model().to(self.device)
        self.model.eval()
        
        self.model_path = model_path
        if os.path.exists(model_path):
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))
            print(f"[*] Loaded Mnemosyne Model from {model_path}")
        else:
            print(f"[!] Warning: Model not found at {model_path}. Running with uninitialized weights (Random).")

    def preprocess(self, payload: bytes):
        """
        Convert raw bytes to fixed-size normalized input for AE.
        Truncates or pads to 1024 bytes.
        """
        # Take first 1024 bytes
        data = list(payload[:1024])
        # Pad with zeros if short
        if len(data) < 1024:
            data += [0] * (1024 - len(data))
        
        # Normalize 0-255 -> 0.0-1.0
        tensor = torch.tensor(data, dtype=torch.float32) / 255.0
        # CNN expects [Batch, Channel, Length] -> [1, 1, 1024]
        return tensor.unsqueeze(0).unsqueeze(0).to(self.device)

    def analyze(self, payload: bytes) -> float:
        """
        Returns threat score (Attack Probability).
        Integrates AI inference with heuristic safety checks.
        """
        if not payload:
            return 0.0

        # --- Stage 1: Heuristic Safety Filter (Reduce False Positives) ---
        # Very broad check for standard GET/POST methods without dangerous symbols
        is_standard_web = False
        if payload.startswith((b"GET /", b"POST /")):
            # If it's a standard method and doesn't contain obvious attack symbols
            # like quotes, semicolons, or script tags, we consider it 'standard'
            if not any(x in payload for x in [b"'", b"\"", b";", b"<", b">", b"../"]):
                is_standard_web = True
        
        # --- Stage 2: Neural Inference ---
        with torch.no_grad():
            inp = self.preprocess(payload)
            logits = self.model(inp)
            probs = torch.softmax(logits, dim=1)
            raw_score = probs[0][1].item()

        # --- Stage 3: Threat Boosters (Catch False Negatives) ---
        dangerous_patterns = [
            b"/etc/passwd", b"cmd.exe", b"/bin/sh", 
            b"SELECT * FROM", b"UNION SELECT",
            b"<script>", b"onerror=", b"javascript:",
            b"curl http", b"wget http"
        ]
        
        boost = 0.0
        for pattern in dangerous_patterns:
            if pattern.lower() in payload.lower():
                boost += 0.5 # Substantial boost

        final_score = raw_score + boost
        
        # If it was marked safe web traffic and AI score is marginal, suppress it
        # This fixes high-score false positives on clean search strings.
        if is_standard_web and final_score < 1.0:
            final_score = min(final_score, 0.1) # Aggressive suppression for safe-looking text

        return min(max(final_score, 0.0), 1.0)

# Global instance for easy import
engine = InferenceEngine()

def analyze_payload(payload: bytes) -> float:
    return engine.analyze(payload)
