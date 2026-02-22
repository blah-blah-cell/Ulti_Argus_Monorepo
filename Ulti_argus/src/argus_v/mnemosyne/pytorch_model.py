import torch
import torch.nn as nn

class PayloadAutoencoder(nn.Module):
    def __init__(self, input_len=1024, latent_dim=64):
        super(PayloadAutoencoder, self).__init__()
        
        # Encoder
        self.encoder = nn.Sequential(
            # [B, 1, 1024]
            nn.Conv1d(1, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool1d(2), # -> [B, 32, 512]
            
            nn.Conv1d(32, 16, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool1d(2), # -> [B, 16, 256]
        )
        
        self.flatten_dim = 16 * 256
        self.fc_enc = nn.Linear(self.flatten_dim, latent_dim)
        
        # Decoder
        self.fc_dec = nn.Linear(latent_dim, self.flatten_dim)
        
        self.decoder = nn.Sequential(
            # [B, 16, 256]
            nn.Upsample(scale_factor=2), # -> [B, 16, 512]
            nn.Conv1d(16, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            
            nn.Upsample(scale_factor=2), # -> [B, 32, 1024]
            nn.Conv1d(32, 1, kernel_size=3, padding=1),
            nn.Sigmoid() # -> [B, 1, 1024]
        )

    def forward(self, x):
        # x: [B, 1, 1024]
        x_enc = self.encoder(x)
        x_flat = x_enc.view(x.size(0), -1)
        latent = self.fc_enc(x_flat)
        
        x_expand = self.fc_dec(latent)
        x_reshape = x_expand.view(x.size(0), 16, 256)
        x_rec = self.decoder(x_reshape)
        return x_rec

    def get_reconstruction_error(self, x):
        # x should be [B, 1, 1024]
        decoded = self.forward(x)
        # MSE over all dimensions per sample
        loss = nn.MSELoss(reduction='none')(decoded, x)
        return torch.mean(loss, dim=[1, 2])

class PayloadClassifier(nn.Module):
    """Binary classifier using the CNN encoder.
    Outputs logits for [normal, attack].
    """
    def __init__(self, input_len=1024, latent_dim=64):
        super(PayloadClassifier, self).__init__()
        # Reuse encoder from autoencoder
        self.encoder = PayloadAutoencoder(input_len=input_len, latent_dim=latent_dim).encoder
        # Encoder output shape after current encoder: [B, 16, 256]
        self.flatten_dim = 16 * 256
        self.fc_enc = nn.Linear(self.flatten_dim, latent_dim)
        self.classifier = nn.Linear(latent_dim, 2)

    def forward(self, x):
        # x: [B, 1, 1024]
        enc = self.encoder(x)
        flat = enc.view(x.size(0), -1)
        latent = self.fc_enc(flat)
        logits = self.classifier(latent)
        return logits

def create_model():
    return PayloadClassifier()
