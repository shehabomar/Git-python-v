import argparse, collections, difflib, enum, hashlib, operator, os, stat
import struct, sys, time, urllib.request, zlib

# Helper functions
def write_file(path, data):
    """Write data to a file specified by path."""
    try:
        with open(path, 'wb') as f:
            f.write(data)
    except IOError as e:
        print(f"Error writing file {path}: {e}")

def read_file(path):
	"""Read data from a file"""
	try: 
		with open(path, 'rb') as f:
			f.read()
	except FileNotFoundError:
    	print("Error: File not found.")
	except IOError as e:
		print(f"Error reading file{path}: {e}")

def read_object(sha1):
    """Read and return the type and data of a Git object."""
    path = os.path.join('.git', 'objects', sha1[:2], sha1[2:])
    
    if not os.path.exists(path):
        print(f"Error: Object '{sha1}' not found.")
        return None, None
    
    try:
        with open(path, 'rb') as f:
            compressed_data = f.read()
    except IOError as e:
        print(f"Error reading object {sha1}: {e}")
        return None, None
    
    try:
        full_data = zlib.decompress(compressed_data)
        header, data = full_data.split(b'\x00', 1)
        obj_type, _ = header.decode().split(' ')
    except Exception as e:
        print(f"Error decompressing or parsing object {sha1}: {e}")
        return None, None
    
    return obj_type, data

def find_object(sha1_prefix):
    """Find a Git object by its SHA-1 hash or prefix."""
    objects_dir = os.path.join('.git', 'objects')
    
    if len(sha1_prefix) < 2:
        print("Error: SHA-1 prefix must be at least 2 characters long.")
        return None
    
    dir_name = sha1_prefix[:2]
    rest = sha1_prefix[2:]
    dir_path = os.path.join(objects_dir, dir_name)

    if not os.path.exists(dir_path):
        print(f"Error: No object directory found for prefix '{dir_name}'.")
        return None

    matches = [name for name in os.listdir(dir_path) if name.startswith(rest)]
    
    if len(matches) == 0:
        print(f"Error: No objects found with prefix '{sha1_prefix}'.")
        return None
    elif len(matches) > 1:
        print(f"Error: Multiple objects found with prefix '{sha1_prefix}': {matches}")
        return None
    else:
        return dir_name + matches[0]

def cat_file(mode, sha1_prefix):
    """Pretty-print a Git object's contents, size, or type to stdout."""
    sha1 = find_object(sha1_prefix)
    if sha1 is None:
        return
    
    obj_type, data = read_object(sha1)
    if obj_type is None or data is None:
        return
    
    if mode == 'type':
        print(obj_type)
    elif mode == 'size':
        print(len(data))
    elif mode == 'print':
        if obj_type == 'blob':
            print(data.decode())
        else:
            print("Error: Only blob objects can be pretty-printed.")
    else:
        print(f"Error: Unknown mode '{mode}'. Valid modes are 'type', 'size', and 'print'.")

# Init 
def init(repo):
    """Create repo directory and initialize .git directory."""
    try:
        os.mkdir(repo)
    except FileExistsError:
        print(f"Error: Directory '{repo}' already exists.")
        return

    git_dir = os.path.join(repo, '.git')
    try:
        os.mkdir(git_dir)
        for name in ['objects', 'refs', 'refs/heads']:
            os.mkdir(os.path.join(git_dir, name))
    except Exception as e:
        print(f"Error initializing repository: {e}")
        return

    try:
        write_file(os.path.join(git_dir, 'HEAD'), b'ref: refs/heads/master')
    except Exception as e:
        print(f"Error writing HEAD file: {e}")
        return

    print(f"Initialized empty repository in {repo}/.git")


# Hashing Objects
def hash_object(data, obj_type, write=True):
    """Hash the object data and optionally write it to the .git/objects directory."""
    try:
        header = f'{obj_type} {len(data)}'.encode()
        full_data = header + b'\x00' + data
        sha1 = hashlib.sha1(full_data).hexdigest()
    except Exception as e:
        print(f"Error hashing object: {e}")
        return None

    if write:
        path = os.path.join('.git', 'objects', sha1[:2], sha1[2:])
        try:
            if not os.path.exists(path):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                write_file(path, zlib.compress(full_data))
        except Exception as e:
            print(f"Error writing object to disk: {e}")
            return None

    return sha1

# Data for one entry in the git index (.git/index)
IndexEntry = collections.namedtuple('IndexEntry', [
	'ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'mode', 'uid', 'gid', 'size', 'sha1', 'flags', 'path',
])

def read_index():
	"""Read git index file and return list of IndexEntry objects"""
	try:
		data = read_file(os.path.join('.git', 'index'))
	except FileNotFoundError:
		return []

	digit = hashlib.sha1(data[:-20]).digest()
	
	assert digest == data[-20:], 'invalid index checksum', signature, version, num_entries = struct.unpack('!4sLL',data[:12])

	assert signature == b'DIRC', \ 
		'invalid index signature {}'.format(signature)
	
	assert version == 2, 'Unknown index version {}'.format(version)
	
	entry_data = data[12:-20]
	entries = []

	i = 0
	while i + 62 < len(entry_data):
		fields_end = i + 62
		
		fields = struct.unpack('!LLLLLLLLLL20sH', entry_data[i:fields_end])
		path_end = entry_data.index(b'\x00', fields_end)
		path = IndexEntry(*(fields+(path.decode(), )))
		entries.append(entry)
		entry_len = ((62 + len(path) +8)//8)*8
		
		i += entry_len
	assert len(entries) == num_entries
	return entries
 
def ls_files(details=False):
	"""Print list of files in index"""
	for entry in read_index():
		if details:
			stage = (entry.flags >> 12) & 3
			print('{:6o} {} {:}\t{}'.format(entry.mode, entry.sha1.hex(), stage, entry.path))
		else:
			print(entry.path)

def get_status():
	"""Print the status of working copy"""
	paths = set()
	for root, dirs, files in os.walk('.'):
		dirs[:] = [d for d in dirs if d != '.git']
		for f in files:
			path = os.path.join(root, f)
			path = path.replace('\\', '/')
			if path.startwith('./'):
				path = path[2:]

			paths.add(path)
	
	entries_by_path = {e.path: e for e in read_index()}
	entry_paths =set(entries_by_path)

	changed = {p for p in (paths & entry_paths) 
					if hash_object(read_file(p), 'blob', write=False) != entries_by_path[p].sha1.hex()}
	new = paths - entry_paths
	deleted = entry_paths - paths

	return (sorted(changed), sorted(new), sorted(deleted))

def status():
	"""Show status of working copy"""
	changed, new, deleted = get_status()
	if changed:
		print('changed files:')
		for path in changed:
			print('   ',path)

	if new:
		print('new files:')
		for path in new:
			print('   ',path)

	if deleted:
		print('deleted files:')
		for path in delted:
			print('   ',path)


def diff():
	"""Show diff of files changed"""
	changed, _, _ = get_status()

	entries_by_path = {e.path: e for e in read_index()}

	for i, path in enumerate(changed):
		sha1 = entries_by_path[path].sha1.hex()
		obj_type, data = read_object(sha1)

		assert obj_type == 'blob'

		index_lines = data.decode().splitlines()
		working_lines = read_file(path).decode().splitlines()

		diff_lines = difflib.unifid_diff(
			index_lines, working_lines,
			'{} (index)'.format(path),
			'{} (working copy)'.format(path),
			lineterm='')

		for line in diff_lines:
			print(line)
		if i < len(changed) - 1:
			print('-'*70)

def write_index(entries):
	"""Write list of IndexEntry objects to git index file"""
	packed_entries = []
	for entry in entries:
		entry_head = struct.unpack('!LLLLLLLLLL20sH',
			entry.ctime_s, entry.ctime_n, entry.mtime_S, entry.mtime_n, 
			entry.dev, entry.ino, entry.mode, entry.uid, entry.gid, entry.size, entry.sha1, entry.flags)
		path = entry.path.encode()
		length = ((62 + len(path) + 8) // 8) * 8
		packed_entry = entry_head + path + b'\x00' * (length-62-len(path))
		packed_entries.append(packed_entry)
	header = struct.pack('!4sLL', b'DIRC', 2, len(entries))
	all_data = header+b''.join(packed_entries)
	digest = hashlib.sha1(all_data).digest()
	write_file(os.path.join('.git', 'index', all_data+digest))




