import requests
import time
def generate_blocks():
    url = "http://localhost:8085/simulator/generate-blocks/1" # 1
    while True:
        try:
            response = requests.post(url)
            if response.status_code == 200:
                print("Successfully sent POST request!")
                print("Response:", response.text)
            else:
                print(f"Failed to send POST request. Status: {response.status_code}")
        except requests.RequestException as e:
            print(f"An error occurred: {e}")
        # Wait 1 second until next request
        time.sleep(1)

if __name__ == "__main__":
    generate_blocks()