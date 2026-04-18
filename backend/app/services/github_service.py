import re
import requests
from typing import Dict
from github import Github, GithubException


class GitHubService:
    """
    Milestone 1: Repository Input & Visibility Detection
    """
    
    def __init__(self, access_token: str = None):
        self.access_token = access_token
        self.github_client = Github(access_token) if access_token else Github()
    
    def parse_github_url(self, url: str) -> Dict[str, str]:
        """
        Parse GitHub repository URL to extract owner and repo name
        """
        # Pattern: https://github.com/owner/repo
        patterns = [
            r'github\.com[:/]([^/]+)/([^/\.]+)',
            r'^([^/]+)/([^/]+)$'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return {
                    "owner": match.group(1),
                    "repo_name": match.group(2).replace('.git', '')
                }
        
        raise ValueError("Invalid GitHub repository URL format")
    
    def validate_repository(self, repo_url: str) -> Dict:
        """
        Validate repository and check if it's public
        Returns repository information
        """
        try:
            # Parse URL
            parsed = self.parse_github_url(repo_url)
            owner = parsed["owner"]
            repo_name = parsed["repo_name"]
            
            # Get repository using GitHub API
            try:
                repo = self.github_client.get_repo(f"{owner}/{repo_name}")
            except GithubException as e:
                if e.status == 404:
                    raise ValueError("Repository not found or is private")
                raise ValueError(f"GitHub API error: {e.data.get('message', 'Unknown error')}")
            
            # Check visibility
            is_public = not repo.private
            
            return {
                "url": repo_url,
                "owner": owner,
                "repo_name": repo_name,
                "is_public": is_public,
                "scan_allowed": is_public,
                "full_name": repo.full_name,
                "description": repo.description or "No description",
                "stars": repo.stargazers_count,
                "language": repo.language or "Unknown"
            }
            
        except ValueError as e:
            raise e
        except Exception as e:
            raise ValueError(f"Error validating repository: {str(e)}")
    
    def get_repository_files(self, owner: str, repo_name: str) -> list:
        """
        Get all file paths from repository
        """
        try:
            repo = self.github_client.get_repo(f"{owner}/{repo_name}")
            contents = repo.get_contents("")
            files = []
            
            print(f"Starting to fetch files from {owner}/{repo_name}...")
            
            while contents:
                file_content = contents.pop(0)
                if file_content.type == "dir":
                    print(f"  Entering directory: {file_content.path}")
                    contents.extend(repo.get_contents(file_content.path))
                else:
                    # Only scan text files
                    if self._is_scannable_file(file_content.name):
                        print(f"  ✓ Adding scannable file: {file_content.path}")
                        files.append({
                            "path": file_content.path,
                            "name": file_content.name,
                            "download_url": file_content.download_url,
                            "size": file_content.size
                        })
                    else:
                        print(f"  ✗ Skipping file: {file_content.path}")
            
            print(f"Total scannable files found: {len(files)}")
            return files
            
        except Exception as e:
            raise ValueError(f"Error fetching repository files: {str(e)}")
    
    def _is_scannable_file(self, filename: str) -> bool:
        """
        Check if file should be scanned
        """
        # Convert to lowercase for case-insensitive comparison
        filename_lower = filename.lower()
        
        # Comprehensive list of text file extensions to scan
        scan_extensions = [
            # Programming languages
            '.js', '.jsx', '.ts', '.tsx',           # JavaScript/TypeScript
            '.py', '.pyw', '.pyx',                  # Python
            '.java', '.class', '.jar',              # Java
            '.go',                                  # Go
            '.rb', '.erb',                          # Ruby
            '.php', '.phtml',                       # PHP
            '.c', '.h', '.cpp', '.hpp', '.cc',      # C/C++
            '.cs', '.csx',                          # C#
            '.swift',                               # Swift
            '.kt', '.kts',                          # Kotlin
            '.rs',                                  # Rust
            '.scala', '.sc',                        # Scala
            '.clj', '.cljs', '.cljc',              # Clojure
            '.ex', '.exs',                          # Elixir
            '.erl', '.hrl',                         # Erlang
            '.hs', '.lhs',                          # Haskell
            '.lua',                                 # Lua
            '.pl', '.pm',                           # Perl
            '.r', '.rmd',                           # R
            '.dart',                                # Dart
            '.vue',                                 # Vue
            
            # Configuration files
            '.env', '.env.local', '.env.production', '.env.development', '.env.test',
            '.config', '.conf', '.cfg',
            '.json', '.json5',
            '.yaml', '.yml',
            '.xml',
            '.toml',
            '.ini',
            '.properties',
            '.editorconfig',
            
            # Shell scripts
            '.sh', '.bash', '.zsh', '.fish',
            
            # Documentation and markup
            '.md', '.markdown', '.mdown', '.mkd',
            '.txt',
            '.html', '.htm',
            '.css', '.scss', '.sass', '.less',
            '.rst',
            
            # Database
            '.sql', '.psql', '.mysql', '.pgsql',
            
            # Other text files
            '.log',
            '.gitignore', '.gitattributes',
            '.dockerignore',
            '.eslintrc', '.prettierrc',
            '.babelrc',
        ]
        
        # Specific filenames to always scan (without extension check)
        scan_filenames = [
            'readme', 'readme.md', 'readme.txt',
            'config', 'configuration',
            'settings',
            '.env', '.env.example', '.env.sample',
            'dockerfile', 'docker-compose.yml',
            'makefile',
            '.gitignore',
            'package.json', 'package-lock.json',
            'composer.json',
            'gemfile',
            'requirements.txt',
            'pipfile',
            'cargo.toml',
            'go.mod',
        ]
        
        # Files/patterns to skip
        skip_patterns = [
            'node_modules/',
            '.git/',
            'vendor/',
            'build/',
            'dist/',
            'target/',
            '.gradle/',
            '.mvn/',
            '__pycache__/',
            '.pytest_cache/',
            'coverage/',
            '.next/',
            '.nuxt/',
            'out/',
            'bin/',
            'obj/',
            '.min.js',
            '.bundle.js',
            '.min.css',
            'yarn.lock',
            'poetry.lock',
            'pipfile.lock',
            'composer.lock',
            'pnpm-lock.yaml',
        ]
        
        # Check if should skip
        for pattern in skip_patterns:
            if pattern in filename_lower:
                return False
        
        # Check specific filenames (exact match)
        if filename_lower in scan_filenames:
            return True
        
        # Check if filename contains certain keywords (for files without clear extensions)
        keyword_patterns = ['readme', 'config', 'secret', 'credential', 'password', 'key', 'token']
        for keyword in keyword_patterns:
            if keyword in filename_lower:
                return True
        
        # Check extension
        for ext in scan_extensions:
            if filename_lower.endswith(ext):
                return True
        
        return False
    
    def get_file_content(self, download_url: str) -> str:
        """
        Download and return file content
        """
        try:
            response = requests.get(download_url, timeout=10)
            response.raise_for_status()
            
            # Try to decode as text
            try:
                content = response.text
                print(f"    Downloaded {len(content)} characters from {download_url.split('/')[-1]}")
                return content
            except UnicodeDecodeError:
                # If binary, skip
                print(f"    Skipped binary file: {download_url.split('/')[-1]}")
                return ""
                
        except Exception as e:
            print(f"    Error downloading file: {str(e)}")
            raise ValueError(f"Error downloading file: {str(e)}")