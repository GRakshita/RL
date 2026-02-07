# train.py — FIXED & VERIFIED LOGIC

import os
import json
import pickle
import shutil
from datetime import datetime

from utils.sandbox import analyze_payload
from utils.generator import generate_payload
from agents.q_agent import QLearningAgent
import config


class EvasionTrainer:
    def __init__(self):
        self._create_output_dirs()

        self.agent = QLearningAgent(epsilon=1.0)

        self.best_score = float("inf")
        self.best_config = None   # (loader, cert, xor_key)

        self.history = []

    # ----------------------------
    # Directory handling
    # ----------------------------
    def _create_output_dirs(self):
        dirs = [
            "outputs",
            "outputs/models",
            "outputs/best_payloads",
            "outputs/history",
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)

    # ----------------------------
    # State encoding
    # ----------------------------
    def _state_to_index(self, loader, cert, xor_key):
        try:
            loader_i = config.LOADERS.index(loader)
            cert_i = config.CERTIFICATES.index(cert)
            xor_i = config.XOR_KEYS.index(xor_key)
        except ValueError:
            return 0

        state_size = len(config.CERTIFICATES) * len(config.XOR_KEYS)
        return loader_i * state_size + cert_i * len(config.XOR_KEYS) + xor_i

    # ----------------------------
    # Training loop
    # ----------------------------
    def train(self, episodes):
        print(f"[+] Starting training for {episodes} episodes")

        for ep in range(episodes):
            loader, cert, xor_key = self.agent.choose_action(None)
            state = self._state_to_index(loader, cert, xor_key)

            try:
                exe_path = generate_payload(loader, cert, xor_key)

                if not os.path.exists(exe_path):
                    raise RuntimeError("Payload generation failed")

                score = analyze_payload(exe_path)
                reward = max(0, 100 - score)

            except Exception as e:
                print(f"[!] Episode {ep} failed: {e}")
                score = 100
                reward = 0

            self.agent.update(state, reward)

            # Track best result
            if score < self.best_score:
                self.best_score = score
                self.best_config = (loader, cert, xor_key)

                print(
                    f"[!] NEW BEST: {score}% "
                    f"(loader={loader}, cert={cert}, key={xor_key})"
                )

                self.history.append({
                    "episode": ep,
                    "loader": loader,
                    "cert": cert,
                    "xor_key": xor_key,
                    "score": score,
                })

            if ep % 10 == 0 or ep == episodes - 1:
                print(f"Ep {ep}: Score={score}% | Epsilon={self.agent.epsilon:.3f}")
                self.save_checkpoint(ep)

        print(f"\n[+] Training complete — Best score: {self.best_score}%")
        self.generate_final_payload()
        self.save_final_model()

    # ----------------------------
    # Final payload
    # ----------------------------
    def generate_final_payload(self):
        if not self.best_config:
            raise RuntimeError("No best configuration found")

        loader, cert, xor_key = self.best_config

        print("[+] Generating final best payload...")
        path = generate_payload(loader, cert, xor_key)

        if not os.path.exists(path):
            raise RuntimeError("Final payload generation failed")

        final_name = f"best_payload_{self.best_score:.0f}%_model.exe"
        final_path = os.path.join("outputs/best_payloads", final_name)

        shutil.move(path, final_path)

        print(f"[+] Saved: {final_path}")
        print(f"[+] Config: {loader}, {cert}, {xor_key}")

    # ----------------------------
    # Checkpointing
    # ----------------------------
    def save_checkpoint(self, episode):
        checkpoint = {
            "q_table": self.agent.q_table,
            "epsilon": self.agent.epsilon,
            "best_score": self.best_score,
            "best_config": self.best_config,
            "episode": episode,
            "timestamp": datetime.now().isoformat(),
        }

        path = f"outputs/models/checkpoint_ep{episode}.pkl"
        with open(path, "wb") as f:
            pickle.dump(checkpoint, f)
            f.flush()
            os.fsync(f.fileno())

        print(f"[+] Checkpoint saved: {path}")

    # ----------------------------
    # Final model
    # ----------------------------
    def save_final_model(self):
        model = {
            "q_table": self.agent.q_table,
            "epsilon": self.agent.epsilon,
            "best_score": self.best_score,
            "best_config": self.best_config,
            "history": self.history,
            "config": {
                "loaders": config.LOADERS,
                "certs": config.CERTIFICATES,
                "xor_keys": config.XOR_KEYS,
            },
        }

        with open("outputs/models/final_agent.pkl", "wb") as f:
            pickle.dump(model, f)
            f.flush()
            os.fsync(f.fileno())

        with open("outputs/history/training_history.json", "w") as f:
            json.dump(self.history, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        print("[+] Final model saved")
        print("[+] Training history saved")


# ----------------------------
# Entrypoint
# ----------------------------
if __name__ == "__main__":
    trainer = EvasionTrainer()
    trainer.train(episodes=config.EPISODES)
