import os
import logging
import requests
import time
from threading import Lock
from pwnagotchi.utils import StatusFile, remove_whitelisted
import pwnagotchi.plugins as plugins

class BetterOnlineHashCrack(plugins.Plugin):
    __author__ = 'silentree12th Updated by: Ev3rPalestine'
    __version__ = '5.6.0'
    __description__ = 'Uploads handshakes with faces and rate control ⏳👾'

    def __init__(self):
        self.ready = False
        self.lock = Lock()
        self.skip = set()
        self.last_upload = 0
        self.rate_limit_hit = False
        self.uploads_this_hour = 0
        self.last_hour_reset = time.time()
        
        try:
            self.report = StatusFile('/root/.ohc_uploads', data_format='json')
        except JSONDecodeError:
            os.remove('/root/.ohc_uploads')
            self.report = StatusFile('/root/.ohc_uploads', data_format='json')

    def on_loaded(self):
        """Validate config when plugin loads"""
        required = ['email', 'api_key']
        for field in required:
            if field not in self.options or not self.options[field]:
                logging.error(f"OHC: {field} is required")
                return

        if not self.options['api_key'].startswith('sk_'):
            logging.error("OHC: API key must start with 'sk_'")
            return

        self.ready = True
        logging.info(f"OHC: Plugin loaded (Rate limit: 30/hour)")

    def _reset_rate_limit(self):
        """Reset hourly counter"""
        if time.time() - self.last_hour_reset >= 3600:
            self.uploads_this_hour = 0
            self.last_hour_reset = time.time()
            logging.info("OHC: Hourly rate limit reset")

    def _update_display(self, agent, message, face=None):
        """Update display with face animation"""
        display = agent.view()
        if face:
            display.set('face', face)
        display.set('status', message)
        display.update(force=True)
        logging.info(f"OHC-DISPLAY: {message}")

    def _read_hash_file(self, agent, hash_file):
        """Read hash file with validation"""
        try:
            with open(hash_file, 'r') as f:
                line = f.readline().strip()
                if not line:
                    self._update_display(agent, 'Empty file!', '(-_-)')
                    logging.error(f"OHC: Empty file: {hash_file}")
                    return None
                if not line.startswith('WPA*'):
                    self._update_display(agent, 'Invalid format!', '(╯°□°)╯')
                    logging.error(f"OHC: Invalid hash format in {hash_file}")
                    return None
                return line
        except Exception as e:
            self._update_display(agent, 'Read error!', '(>_<)')
            logging.error(f"OHC: Failed to read {hash_file}: {str(e)}")
            return None

    def _submit_hash(self, agent, hash22000):
        """Submit hash with strict rate control"""
        self._reset_rate_limit()
        
        # Hard limit: 30/hour
        if self.uploads_this_hour >= 30:
            wait_time = 3600 - (time.time() - self.last_hour_reset)
            self._update_display(agent, f'Limit reached!\nWait {int(wait_time/60)}m', '(⌐■_■)')
            logging.warning(f"OHC: Hourly limit reached (30 uploads)")
            time.sleep(wait_time)
            return False

        if self.rate_limit_hit:
            self._update_display(agent, 'Rate limited!\nWaiting 5m...', '(︶︹︺)')
            logging.warning("OHC: Rate limit cooldown (5m)")
            time.sleep(300)
            self.rate_limit_hit = False

        # Minimum 12s between requests (30/hour = 1/120s)
        if time.time() - self.last_upload < 12:
            delay = 12 - (time.time() - self.last_upload)
            self._update_display(agent, f'Waiting {int(delay)}s...', '(￣ω￣)')
            time.sleep(delay)

        url = "https://api.onlinehashcrack.com/v2"
        headers = {"Content-Type": "application/json"}
        data = {
            "api_key": self.options['api_key'],
            "agree_terms": "yes",
            "algo_mode": 22000,
            "hashes": [hash22000],
            "email": self.options['email']
        }

        try:
            self._update_display(agent, 'Uploading...', '(◕‿◕)')
            response = requests.post(url, json=data, headers=headers, timeout=30)
            
            if response.status_code == 200:
                self.last_upload = time.time()
                self.uploads_this_hour += 1
                self._update_display(agent, 'Uploaded!', '(ᵔ◡◡ᵔ)')
                logging.info(f"OHC: Uploaded (Total: {self.uploads_this_hour}/30)")
                time.sleep(1)
                return True
                
            elif response.status_code == 429:
                self.rate_limit_hit = True
                self._update_display(agent, 'Rate limited!\nWaiting 5m...', '(︶︹︺)')
                logging.warning("OHC: Rate limit hit - waiting 5m")
                time.sleep(300)
                return False
                
            else:
                error_msg = response.json().get('message', 'Unknown error')
                self._update_display(agent, f'API Error:\n{error_msg[:15]}...', '(×_×)')
                logging.error(f"OHC: API Error {response.status_code}: {error_msg}")
                
        except Exception as e:
            self._update_display(agent, 'Connection failed', '(×﹏×)')
            logging.error(f"OHC: Connection Failed: {str(e)}")
            
        return False

    def on_internet_available(self, agent):
        """Main processing with faces and rate control"""
        if not self.ready or self.lock.locked():
            return

        with self.lock:
            config = agent.config()
            handshake_dir = config['bettercap']['handshakes']
            whitelist = self.options.get('whitelist', [])
            
            # Get processable files
            all_files = os.listdir(handshake_dir)
            hash_files = [
                f for f in all_files 
                if f.endswith('.22000') 
                and f"{f}.uploaded" not in all_files
            ]

            # Apply whitelist
            hash_files = [
                hf for hf in hash_files
                if remove_whitelisted([hf.replace('.22000', '.pcap')], whitelist)
            ]

            if not hash_files:
                self._update_display(agent, 'No new handshakes', '(￣ヘ￣)')
                time.sleep(2)
                agent.view().on_normal()
                return

            self._update_display(agent, f'Found {len(hash_files)}\nReady to upload!', '(◠‿◠)')
            time.sleep(2)
            
            processed = 0
            for idx, filename in enumerate(hash_files, 1):
                hash_file = os.path.join(handshake_dir, filename)
                
                # Show progress
                self._update_display(agent, f'{idx}/{len(hash_files)}', '(☉_☉)')
                
                hash22000 = self._read_hash_file(agent, hash_file)
                if not hash22000:
                    continue
                    
                if self._submit_hash(agent, hash22000):
                    open(f"{hash_file}.uploaded", 'w').close()
                    processed += 1
                else:
                    break  # Stop on critical errors

            # Final status
            if processed > 0:
                self._update_display(agent, f'Done!\n{processed} uploaded', '(ᵔ◡◡ᵔ)')
            else:
                self._update_display(agent, 'No uploads\ncompleted', '(╥_╥)')
            time.sleep(3)
            agent.view().on_normal()
