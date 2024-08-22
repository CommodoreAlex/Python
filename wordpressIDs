# Brute forcing IDs on for wordpress targets for CTFs
import requests

url = 'http://blog.inlanefreight.local/?author=' # Target URL
headers = {
    'User-Agent': 'Mozilla/5.0'
}

# Loop through IDs from 1 to 100
for i in range(1, 101:
    try:
        # Construct the full URL with the current ID
        full_url = f'{url}{i}'

        # Send the request
        response = requests.get(full_url, headers=headers)

        #C Check to see if request was successful
        if response.status_code == 200:
            print(f'Valid ID found: {i}')
            # Print hte response content if necessary
            #print(response.content.decode())
        else:
            print(f'ID {i} not valid, status code: {response.status_code}')
    except requests.exceptions.RequestException as e:
        print(f'Error with ID {i}: {e}')
        
print("Brute forcing complete. \n")
