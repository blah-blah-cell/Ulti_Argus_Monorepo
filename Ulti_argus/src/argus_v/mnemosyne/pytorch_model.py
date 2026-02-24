"""Mnemosyne deep-learning models for payload analysis.

Provides two architectures:

* **PayloadAutoencoder** – unsupervised anomaly detection via reconstruction
  error.  High reconstruction loss ⇒ payload looks unlike anything in the
  training set.
* **PayloadClassifier** – supervised binary classifier (benign / malicious).
  Uses a deeper convolutional encoder with batch-normalisation, dropout, and
  a channel-attention squeeze-excite block for better generalisation.

Both models operate on raw byte sequences of length *input_len* (default 1024),
normalised to ``[0, 1]`` and shaped ``[B, 1, input_len]``.
"""

import torch.nn as nn
import torch.nn.functional as F

# ──────────────────────────────────────────────────────────────────────────
#  Building blocks
# ──────────────────────────────────────────────────────────────────────────

class _ConvBlock(nn.Module):
    """Conv1d → BatchNorm → ReLU → optional MaxPool."""

    def __init__(self, in_ch: int, out_ch: int, kernel: int = 3, pool: int = 2):
        super().__init__()
        self.conv = nn.Conv1d(in_ch, out_ch, kernel_size=kernel, padding=kernel // 2)
        self.bn = nn.BatchNorm1d(out_ch)
        self.pool = nn.MaxPool1d(pool) if pool > 1 else nn.Identity()

    def forward(self, x):
        return self.pool(F.relu(self.bn(self.conv(x))))


class _SqueezeExcite(nn.Module):
    """Channel-attention (SE) block — learns per-channel importance."""

    def __init__(self, channels: int, reduction: int = 4):
        super().__init__()
        mid = max(channels // reduction, 1)
        self.fc = nn.Sequential(
            nn.AdaptiveAvgPool1d(1),
            nn.Flatten(),
            nn.Linear(channels, mid),
            nn.ReLU(inplace=True),
            nn.Linear(mid, channels),
            nn.Sigmoid(),
        )

    def forward(self, x):
        # x: [B, C, L]
        scale = self.fc(x).unsqueeze(-1)  # [B, C, 1]
        return x * scale


# ──────────────────────────────────────────────────────────────────────────
#  Encoder (shared between autoencoder and classifier)
# ──────────────────────────────────────────────────────────────────────────

class _Encoder(nn.Module):
    """4-layer convolutional encoder.

    Input  : [B, 1, 1024]
    Output : [B, 64, 64]   (before flattening)
    """

    def __init__(self):
        super().__init__()
        self.layers = nn.Sequential(
            _ConvBlock(1, 32, kernel=7, pool=2),    # [B,  32, 512]
            _ConvBlock(32, 64, kernel=5, pool=2),   # [B,  64, 256]
            _ConvBlock(64, 64, kernel=3, pool=2),   # [B,  64, 128]
            _ConvBlock(64, 64, kernel=3, pool=2),   # [B,  64,  64]
            _SqueezeExcite(64),
        )

    def forward(self, x):
        return self.layers(x)


# ──────────────────────────────────────────────────────────────────────────
#  Autoencoder (unsupervised anomaly scoring)
# ──────────────────────────────────────────────────────────────────────────


class PayloadAutoencoder(nn.Module):
    """Conv autoencoder for payload anomaly detection.

    Compresses a 1024-byte sequence to a *latent_dim*-dimensional vector
    and reconstructs it.  The per-sample MSE reconstruction error can serve
    as an anomaly score.
    """

    def __init__(self, input_len: int = 1024, latent_dim: int = 64):
        super().__init__()
        self.encoder = _Encoder()                       # → [B, 64, 64]
        self._enc_flat = 64 * 64                        # 4096
        self.fc_enc = nn.Linear(self._enc_flat, latent_dim)
        self.fc_dec = nn.Linear(latent_dim, self._enc_flat)

        self.decoder = nn.Sequential(
            nn.Upsample(scale_factor=2),                # [B, 64, 128]
            nn.Conv1d(64, 64, 3, padding=1), nn.BatchNorm1d(64), nn.ReLU(),
            nn.Upsample(scale_factor=2),                # [B, 64, 256]
            nn.Conv1d(64, 32, 3, padding=1), nn.BatchNorm1d(32), nn.ReLU(),
            nn.Upsample(scale_factor=2),                # [B, 32, 512]
            nn.Conv1d(32, 16, 3, padding=1), nn.BatchNorm1d(16), nn.ReLU(),
            nn.Upsample(scale_factor=2),                # [B, 16, 1024]
            nn.Conv1d(16, 1, 3, padding=1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        enc = self.encoder(x)
        flat = enc.view(x.size(0), -1)
        latent = self.fc_enc(flat)
        dec_in = F.relu(self.fc_dec(latent)).view(x.size(0), 64, 64)
        return self.decoder(dec_in)

    def get_reconstruction_error(self, x):
        """Per-sample MSE reconstruction error (anomaly score)."""
        recon = self.forward(x)
        return F.mse_loss(recon, x, reduction="none").mean(dim=[1, 2])


# ──────────────────────────────────────────────────────────────────────────
#  Classifier (supervised binary: benign / malicious)
# ──────────────────────────────────────────────────────────────────────────

class PayloadClassifier(nn.Module):
    """Binary threat classifier over raw payload bytes.

    Architecture
    ------------
    * 4-layer conv encoder with BN + SE attention
    * Global average pooling → latent vector
    * MLP head with dropout → 2-class logits
    """

    def __init__(self, input_len: int = 1024, latent_dim: int = 128, dropout: float = 0.3):
        super().__init__()
        self.encoder = _Encoder()                       # → [B, 64, 64]
        self.gap = nn.AdaptiveAvgPool1d(1)              # → [B, 64, 1]

        self.head = nn.Sequential(
            nn.Flatten(),                               # → [B, 64]
            nn.Linear(64, latent_dim),
            nn.ReLU(inplace=True),
            nn.Dropout(dropout),
            nn.Linear(latent_dim, 64),
            nn.ReLU(inplace=True),
            nn.Dropout(dropout * 0.5),
            nn.Linear(64, 2),                           # logits
        )

    def forward(self, x):
        enc = self.encoder(x)       # [B, 64, 64]
        pooled = self.gap(enc)      # [B, 64, 1]
        return self.head(pooled)


# ──────────────────────────────────────────────────────────────────────────
#  Factory helpers
# ──────────────────────────────────────────────────────────────────────────

def create_model(kind: str = "classifier", **kwargs) -> nn.Module:
    """Create a Mnemosyne model by *kind*.

    Args:
        kind: ``"classifier"`` or ``"autoencoder"``
    """
    if kind == "classifier":
        return PayloadClassifier(**kwargs)
    elif kind == "autoencoder":
        return PayloadAutoencoder(**kwargs)
    raise ValueError(f"Unknown model kind: {kind!r}")
