# agents/q_agent.py - Fixed with epsilon-greedy support
import numpy as np
import random
import config

class QLearningAgent:
    def __init__(self, learning_rate=0.1, discount=0.9, epsilon=1.0, epsilon_min=0.01, epsilon_decay=0.995):
        # Q-table: state -> value (single value per state since action space is implicit)
        self.q_table = {}
        self.alpha = learning_rate
        self.gamma = discount
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        
    def get_state_value(self, state):
        """Get Q-value for state (default 0 if unseen)"""
        return self.q_table.get(state, 0.0)
    
    def choose_action(self, state):
        """Epsilon-greedy action selection"""
        if random.random() < self.epsilon:
            # Exploration: random action (loader, cert, xor_key)
            return (random.choice(config.LOADERS),
                   random.choice(config.CERTIFICATES),
                   random.choice(config.XOR_KEYS))
        else:
            # Exploitation: best known action
            best_state = max(self.q_table.keys(), 
                           key=lambda s: self.q_table[s], 
                           default=0)
            return self.state_to_action(best_state)
    
    def state_to_action(self, state_idx):
        """Convert state index back to (loader, cert, xor_key)"""
        state_size = len(config.CERTIFICATES) * len(config.XOR_KEYS)
        loader_idx = state_idx // state_size
        cert_idx = (state_idx // len(config.XOR_KEYS)) % len(config.CERTIFICATES)
        xor_idx = state_idx % len(config.XOR_KEYS)
        
        return (config.LOADERS[loader_idx],
                config.CERTIFICATES[cert_idx],
                config.XOR_KEYS[xor_idx])
    
    def update(self, state, reward):
        """Update Q-value for state"""
        old_value = self.get_state_value(state)
        new_value = old_value + self.alpha * (reward - old_value)
        self.q_table[state] = new_value
        
        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
    
    def get_best_action(self):
        """Get the single best action from Q-table"""
        if not self.q_table:
            return (random.choice(config.LOADERS),
                   random.choice(config.CERTIFICATES),
                   random.choice(config.XOR_KEYS))
        
        best_state = max(self.q_table.keys(), key=lambda s: self.q_table[s])
        return self.state_to_action(best_state)
