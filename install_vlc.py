import requests
import hashlib
import subprocess
import os

def main():
    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):
        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    # Step 1
    # Send GET message to download the file
    url = 'http://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/SHA256SUMS'
    resp = requests.get(url)
    if resp.status_code == requests.codes.ok:
        file_content = resp.text
        sha256_lines = [line for line in file_content.split('\n') if '.exe' in line]
        if sha256_lines:
            expected_sha256 = sha256_lines[0].split()[0]
            return expected_sha256
    return None

def download_installer():
    """Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    #  Step 2
    # Send GET message to download the file
    file_url = 'http://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe'
    resp_msg = requests.get(file_url)
    if resp_msg.status_code == requests.codes.ok:
        return resp_msg.content
    return None

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expected SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    if installer_data is not None and expected_sha256 is not None:
        computed_sha256 = hashlib.sha256(installer_data).hexdigest()
        return computed_sha256 == expected_sha256
    return False

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    file_path = r'C:\Temp\vlc_installer.exe'  
    with open(file_path, 'wb') as file:
        file.write(installer_data)
    return file_path

def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    subprocess.run([installer_path])

def delete_installer(installer_path):
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    os.remove(installer_path)

if __name__ == '__main__':
    main()