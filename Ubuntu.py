#!/usr/bin/env python3
"""
Enhanced Ubuntu Image Fetcher
Building upon the starter code with advanced features for mindful web community interaction

This enhanced version addresses:
- Multiple URL handling
- Security precautions for unknown sources
- Duplicate prevention
- HTTP header validation
- Ubuntu principles implementation
"""

import requests
import os
import hashlib
import json
from urllib.parse import urlparse
from pathlib import Path
import mimetypes


class UbuntuImageFetcher:
    """Ubuntu Image Fetcher with enhanced community-minded features."""
    
    def __init__(self):
        self.directory = "Fetched_Images"
        self.metadata_file = os.path.join(self.directory, ".image_metadata.json")
        self.downloaded_hashes = self.load_downloaded_hashes()
        
        # Security settings - Ubuntu principle of respect for community safety
        self.max_file_size = 50 * 1024 * 1024  # 50MB limit
        self.allowed_content_types = {
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 
            'image/webp', 'image/bmp', 'image/tiff', 'image/svg+xml'
        }
        self.suspicious_extensions = {
            '.exe', '.bat', '.cmd', '.scr', '.pif', '.com', 
            '.js', '.vbs', '.jar', '.zip', '.rar'
        }
        
    def load_downloaded_hashes(self):
        """Load previously downloaded image hashes to prevent duplicates."""
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    return data.get('hashes', {})
        except Exception:
            pass
        return {}
    
    def save_downloaded_hashes(self):
        """Save downloaded image hashes for duplicate prevention."""
        try:
            os.makedirs(self.directory, exist_ok=True)
            metadata = {'hashes': self.downloaded_hashes}
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            print(f"⚠ Could not save metadata: {e}")
    
    def calculate_file_hash(self, content):
        """Calculate SHA256 hash of file content for duplicate detection."""
        return hashlib.sha256(content).hexdigest()
    
    def validate_url_security(self, url):
        """Implement security precautions for unknown sources - Ubuntu principle of respect."""
        parsed_url = urlparse(url)
        
        # Check for suspicious URL patterns
        if not parsed_url.scheme in ['http', 'https']:
            return False, "Only HTTP and HTTPS URLs are supported for security"
        
        # Check for suspicious file extensions in URL
        path_lower = parsed_url.path.lower()
        for ext in self.suspicious_extensions:
            if path_lower.endswith(ext):
                return False, f"Suspicious file extension detected: {ext}"
        
        # Warn about non-HTTPS connections
        if parsed_url.scheme == 'http':
            print("⚠ Warning: Non-encrypted HTTP connection detected")
            choice = input("Continue with potentially insecure connection? (y/n): ").lower()
            if choice != 'y':
                return False, "User chose not to proceed with insecure connection"
        
        return True, "URL passes security validation"
    
    def validate_http_headers(self, response):
        """Check important HTTP headers before saving content - Ubuntu principle of mindfulness."""
        headers = response.headers
        
        # 1. Content-Type validation
        content_type = headers.get('content-type', '').lower().split(';')[0]
        if content_type not in self.allowed_content_types:
            return False, f"Invalid content type: {content_type}. Expected image format."
        
        # 2. Content-Length validation (file size check)
        content_length = headers.get('content-length')
        if content_length and int(content_length) > self.max_file_size:
            size_mb = int(content_length) / (1024 * 1024)
            return False, f"File too large: {size_mb:.1f}MB (max: {self.max_file_size/(1024*1024)}MB)"
        
        # 3. Content-Disposition check for filename
        content_disposition = headers.get('content-disposition', '')
        suggested_filename = None
        if 'filename=' in content_disposition:
            try:
                suggested_filename = content_disposition.split('filename=')[1].strip('"\'')
            except:
                pass
        
        # 4. Security headers check
        security_info = []
        if headers.get('x-content-type-options') == 'nosniff':
            security_info.append("Content type validation enforced")
        
        if headers.get('content-security-policy'):
            security_info.append("Content Security Policy present")
        
        return True, {
            'content_type': content_type,
            'content_length': content_length,
            'suggested_filename': suggested_filename,
            'security_info': security_info
        }
    
    def extract_filename(self, url, headers_info=None, content_type=None):
        """Extract filename from URL or generate one - enhanced version."""
        # Try suggested filename from headers first
        if headers_info and headers_info.get('suggested_filename'):
            filename = headers_info['suggested_filename']
        else:
            # Extract from URL
            parsed_url = urlparse(url)
            filename = os.path.basename(parsed_url.path)
        
        # Generate filename if none found
        if not filename or filename == '/':
            filename = "ubuntu_fetched_image"
        
        # Ensure proper extension based on content type
        if content_type and '.' not in filename:
            extension_map = {
                'image/jpeg': '.jpg',
                'image/png': '.png',
                'image/gif': '.gif',
                'image/webp': '.webp',
                'image/bmp': '.bmp',
                'image/tiff': '.tiff',
                'image/svg+xml': '.svg'
            }
            extension = extension_map.get(content_type, '.jpg')
            filename += extension
        
        # Sanitize filename for safety
        filename = "".join(c for c in filename if c.isalnum() or c in '._-')
        
        return filename
    
    def download_single_image(self, url):
        """Download a single image with all Ubuntu principles and security measures."""
        print(f"\nProcessing: {url}")
        
        try:
            # Security validation
            is_safe, security_message = self.validate_url_security(url)
            if not is_safe:
                print(f"✗ Security check failed: {security_message}")
                return False
            
            # Create directory if it doesn't exist
            os.makedirs(self.directory, exist_ok=True)
            
            # Fetch the image with respectful headers
            headers = {
                'User-Agent': 'Ubuntu Image Fetcher - Community Respectful Tool/1.0',
                'Accept': 'image/*',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            }
            
            print("Connecting respectfully to the web community...")
            response = requests.get(url, timeout=10, headers=headers, stream=True)
            response.raise_for_status()  # Raise exception for bad status codes
            
            # Validate HTTP headers
            is_valid, header_info = self.validate_http_headers(response)
            if not is_valid:
                print(f"✗ Header validation failed: {header_info}")
                return False
            
            print("✓ Security and header validation passed")
            
            # Download content with size monitoring
            content = b''
            downloaded_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                downloaded_size += len(chunk)
                
                # Real-time size check for safety
                if downloaded_size > self.max_file_size:
                    print(f"✗ File size exceeded limit during download")
                    return False
            
            # Check for duplicates using content hash
            content_hash = self.calculate_file_hash(content)
            if content_hash in self.downloaded_hashes:
                existing_file = self.downloaded_hashes[content_hash]
                print(f"✓ Image already exists as: {existing_file}")
                print("✓ Duplicate prevented - respecting storage efficiency")
                return True
            
            # Extract filename with enhanced logic
            content_type = header_info.get('content_type')
            filename = self.extract_filename(url, header_info, content_type)
            
            # Handle filename conflicts
            original_filename = filename
            counter = 1
            while os.path.exists(os.path.join(self.directory, filename)):
                name, ext = os.path.splitext(original_filename)
                filename = f"{name}_{counter}{ext}"
                counter += 1
            
            # Save the image
            filepath = os.path.join(self.directory, filename)
            with open(filepath, 'wb') as f:
                f.write(content)
            
            # Update hash database
            self.downloaded_hashes[content_hash] = filename
            self.save_downloaded_hashes()
            
            # Success reporting
            file_size = len(content)
            if file_size > 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            elif file_size > 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = f"{file_size} bytes"
            
            print(f"✓ Successfully fetched: {filename}")
            print(f"✓ Image saved to {filepath}")
            print(f"✓ File size: {size_str}")
            print(f"✓ Content type: {content_type}")
            
            # Display security information if available
            if header_info.get('security_info'):
                print(f"✓ Security features: {', '.join(header_info['security_info'])}")
            
            return True
            
        except requests.exceptions.Timeout:
            print("✗ Connection timeout - the community server may be busy")
        except requests.exceptions.ConnectionError:
            print("✗ Connection error - please check your network and URL")
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response else "Unknown"
            print(f"✗ HTTP Error {status_code} - server respectfully declined request")
        except requests.exceptions.RequestException as e:
            print(f"✗ Request error: {e}")
        except OSError as e:
            print(f"✗ File system error: {e}")
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
        
        return False
    
    def download_multiple_images(self, urls):
        """Handle multiple URLs with Ubuntu community spirit."""
        print(f"\nPreparing to fetch {len(urls)} images from the web community")
        print("=" * 50)
        
        successful_downloads = 0
        total_urls = len(urls)
        
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{total_urls}] Processing URL:")
            if self.download_single_image(url.strip()):
                successful_downloads += 1
            print("-" * 30)
        
        # Summary with Ubuntu spirit
        print(f"\n🌍 Community Connection Summary:")
        print(f"✓ Successfully fetched: {successful_downloads}/{total_urls} images")
        print(f"✓ Images organized in: {self.directory}")
        print(f"✓ Duplicates prevented: {len(self.downloaded_hashes)} unique images tracked")
        
        if successful_downloads > 0:
            print("\nConnection strengthened. Community enriched.")
        else:
            print("\nConnections attempted with respect. Community spirit maintained.")


def main():
    """Main function implementing the Ubuntu Image Fetcher with enhancements."""
    print("Welcome to the Ubuntu Image Fetcher")
    print("A tool for mindfully collecting images from the web")
    print()
    
    fetcher = UbuntuImageFetcher()
    
    # Ask user for input method
    print("Choose your approach:")
    print("1. Single image URL")
    print("2. Multiple image URLs (one per line, empty line to finish)")
    print("3. Read URLs from file")
    
    choice = input("\nEnter your choice (1/2/3): ").strip()
    
    if choice == "1":
        # Single URL - following original starter structure
        url = input("Please enter the image URL: ")
        if url.strip():
            if fetcher.download_single_image(url.strip()):
                print("\nConnection strengthened. Community enriched.")
            else:
                print("\nConnection attempted with respect.")
    
    elif choice == "2":
        # Multiple URLs input
        print("\nEnter image URLs (one per line, empty line to finish):")
        urls = []
        while True:
            url = input("URL: ").strip()
            if not url:
                break
            urls.append(url)
        
        if urls:
            fetcher.download_multiple_images(urls)
        else:
            print("No URLs provided. Community connection maintained in readiness.")
    
    elif choice == "3":
        # Read from file
        filename = input("Enter filename containing URLs: ").strip()
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if urls:
                print(f"Loaded {len(urls)} URLs from {filename}")
                fetcher.download_multiple_images(urls)
            else:
                print("No valid URLs found in file.")
        
        except FileNotFoundError:
            print(f"✗ File '{filename}' not found")
        except Exception as e:
            print(f"✗ Error reading file: {e}")
    
    else:
        print("Invalid choice. Ubuntu spirit suggests trying again with mindfulness.")


if __name__ == "__main__":
    main()
