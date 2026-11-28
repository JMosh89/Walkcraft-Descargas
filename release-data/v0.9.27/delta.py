#!/usr/bin/env python3
"""Transfer an exact signed APK using data-only ZIP copy and literal ranges."""
import argparse
import gzip
import hashlib
import json
import mmap
import struct
import zipfile
from pathlib import Path

MAGIC = b'WALKCRAFT-APK\x01'
CHUNK = 1 << 20
BASE = {'url':'https://github.com/JMosh89/Walkcraft-Descargas/releases/download/v0.9.23/Walkcraft-Android-0.9.23-Normal.apk',
        'size':266024606,'sha256':'3b02b0795ab61cc6a72df7a8fd49ba2924e4718c97caf9f5ead52bfeacd03c6e'}
ASSET = 'Walkcraft-Android-0.9.27-Normal.apk'
MAX_FILE_SIZE = 320_000_000


def digest(path):
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def package_position(zinfo, file):
    start = zinfo.header_offset
    if file[start:start+4] != b'PK\x03\x04':
        raise ValueError('Invalid ZIP entry')
    name_len, extra_len = struct.unpack_from('<HH', file, start+26)
    begin = start+30+name_len+extra_len
    end = begin+zinfo.compress_size
    if end > len(file):
        raise ValueError('ZIP entry outside APK')
    return start, begin, end


def identity_matches(path, expected):
    return Path(path).stat().st_size == expected['size'] and digest(path) == expected['sha256']


def generate(old_path, new_path, patch_path):
    if not identity_matches(old_path, BASE):
        raise ValueError('Incorrect public baseline APK')
    if Path(new_path).name != ASSET:
        raise ValueError('Incorrect signed APK name')
    with open(old_path,'rb') as old, open(new_path,'rb') as new, \
        mmap.mmap(old.fileno(),0,access=mmap.ACCESS_READ) as old_data, \
        mmap.mmap(new.fileno(),0,access=mmap.ACCESS_READ) as new_data, \
        zipfile.ZipFile(old) as old_zip, zipfile.ZipFile(new) as new_zip, \
        open(patch_path,'xb') as patch_disk, gzip.GzipFile(filename='',fileobj=patch_disk,mode='wb',mtime=0,compresslevel=5) as patch:
        positions = {}
        for entry in old_zip.infolist():
            if entry.compress_size:
                start, begin, end = package_position(entry,old_data)
                key=(entry.CRC,entry.file_size,entry.compress_size,entry.compress_type)
                positions.setdefault(key,[]).append((begin,end))
        patch.write(MAGIC)
        cursor = copied = literal = 0
        for entry in sorted(new_zip.infolist(), key=lambda item:item.header_offset):
            start, begin, end = package_position(entry,new_data)
            if start < cursor:
                continue
            key=(entry.CRC,entry.file_size,entry.compress_size,entry.compress_type)
            candidates = positions.get(key,())
            for previous, previous_end in candidates:
                if new_data[begin:end] != old_data[previous:previous_end]:
                    continue
                if begin > cursor:
                    patch.write(b'L'+struct.pack('>Q',begin-cursor))
                    patch.write(new_data[cursor:begin])
                    literal += begin-cursor
                patch.write(b'C'+struct.pack('>QQ',previous,end-begin))
                copied += end-begin
                cursor=end
                break
        if len(new_data) > cursor:
            patch.write(b'L'+struct.pack('>Q',len(new_data)-cursor))
            patch.write(new_data[cursor:])
            literal += len(new_data)-cursor
        patch.write(b'E')
    return {'copied':copied,'literal':literal,'patch_sha256':digest(patch_path),
            'patch_size':Path(patch_path).stat().st_size}


def exact_read(file, n):
    buf=file.read(n)
    if len(buf)!=n:
        raise ValueError('Truncated patch')
    return buf


def apply(old_path, patch_path, out, meta_path):
    meta=json.loads(Path(meta_path).read_text())
    output=meta['output']
    if meta['tag']!='v0.9.27' or meta['base']!=BASE or output['name']!=ASSET or not 1<=output['size']<=MAX_FILE_SIZE:
        raise ValueError('Unexpected release identity')
    if not identity_matches(old_path, BASE) or digest(patch_path)!=meta['patch_sha256']:
        raise ValueError('Baseline APK or update transfer checksum mismatch')
    out=Path(out)
    if out.exists():
        raise ValueError('Output already exists')
    size=ops=0
    try:
        with open(old_path,'rb') as base, gzip.open(patch_path,'rb') as patch, out.open('xb') as target:
            if exact_read(patch,len(MAGIC))!=MAGIC:
                raise ValueError('Invalid patch format')
            while (op:=exact_read(patch,1))!=b'E':
                ops+=1
                if ops>10_000:
                    raise ValueError('Too many patch operations')
                if op==b'C':
                    off,length=struct.unpack('>QQ',exact_read(patch,16))
                    if off+length>BASE['size']:
                        raise ValueError('Baseline copy range is invalid')
                    base.seek(off)
                    src=base
                elif op==b'L':
                    length,=struct.unpack('>Q',exact_read(patch,8))
                    src=patch
                else:
                    raise ValueError('Invalid patch instruction')
                size+=length
                if length==0 or size>output['size']:
                    raise ValueError('Invalid reconstructed size')
                while length:
                    block=exact_read(src,min(length,CHUNK))
                    target.write(block)
                    length-=len(block)
            if patch.read(1):
                raise ValueError('Extra patch data')
        if not identity_matches(out,output):
            raise ValueError('Reconstructed APK differs from the signed APK')
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['generate','apply'])
    parser.add_argument('baseline')
    parser.add_argument('input')
    parser.add_argument('output')
    parser.add_argument('--metadata')
    a=parser.parse_args()
    result=generate(a.baseline,a.input,a.output) if a.mode=='generate' else apply(a.baseline,a.input,a.output,a.metadata)
    print(json.dumps(result,sort_keys=True))
