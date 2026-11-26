import sys
import os

# Añadir el directorio raíz al path para importar los módulos de omega
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omega.federation_discovery_engine import discovery

def run_crawler():
    print("========================================")
    print("[AUTONOMOUS CRON] Iniciando ciclo de caza...")
    total = discovery.hunt_new_nodes()
    print(f"[AUTONOMOUS CRON] Ciclo terminado. Total de nodos en el cuerpo: {total}")
    print("========================================")

if __name__ == "__main__":
    run_crawler()
