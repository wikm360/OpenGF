import requests
import yaml
from typing import Dict
import json

def load_yaml(file_path: str) -> Dict:
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def send_to_telegram (mess) :
    config = load_yaml("./settings/config.yaml")
    token =  config['telegram']['token']
    chat_id = config['telegram']['chatid']
    if not token == "None" :
        result  = requests.get("https://api.telegram.org/bot" + token + "/sendMessage" + "?chat_id=" + chat_id + "&text=" + mess)
        content = result.content.decode('utf-8')
        data_dict = json.loads(content)
        print(f"telegram result: {data_dict['ok']}")
    else :
        pass
