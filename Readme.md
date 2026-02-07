
## In Windows VM or Windows OS ( WINDOWS ONLY )

    Install litterbox. Installation steps are given in the repositary itself. 
    Litterbox repo link : https://github.com/BlackSnufkin/LitterBox

### In folder "RL" ( ON LINUX : Attacker )
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

### Make directories
    mkdir -p /tmp/outputs/models
    mkdir -p /tmp/outputs/best_payloads
    mkdir -p /tmp/outputs/history
    
Start Litterbox. 
Edit the config.py file in RL folder. 
Run `python train.py`.
After completion of the execution, the final .exe file is in `/tmp/outputs/best_payloads/`