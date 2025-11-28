#!/usr/bin/env python3
"""
zerowidthstego.py
Author: Ridpath
License: MIT
Repo: https://github.com/ridpath/ZeroWidthStego

Description:
  Provides modular stego encoding/decoding/detection across various Unicode based covert channels.

‌‌‌‌‌‌‌‌‌​​‌​‌‌‌‌‌‌‌‌‌‌‌‌​​​‌​‌‌‌‌‌‌‌‌‌‌‌​​​‌​‌‌‌‌‌‌‌‌‌‌‌​​​‌‌‌‌‌‌‌‌‌‌‌‌‌​​​‌‌​​‌‌‌‌‌‌‌‌‌‌​​​‌​‌‌‌‌‌‌‌‌‌‌‌​‌​​​​‌‌‌‌‌‌‌‌‌‌​‌​​​​‌‌‌‌‌‌‌‌‌​​‌‌​​​‌‌‌‌‌‌‌‌‌​​‌​‌‌​‌‌‌‌‌‌‌‌‌​​​‌​‌‌‌‌‌‌‌‌‌‌‌​​‌​‌‌‌‌‌‌‌‌‌‌‌‌​​​‌​‌​‌‌‌‌‌‌‌‌‌​​‌‌‌​‌‌‌‌‌‌‌‌‌‌‌​‌​​​‌‌‌‌‌‌‌‌‌‌​​‌‌‌​​‌‌‌‌‌‌‌‌‌​​‌​​​​‌‌‌‌‌‌‌‌‌​​‌​​‌​‌‌‌‌‌‌‌‌‌‌​‌​​​​‌‌‌‌‌‌‌‌‌​​​‌‌​‌‌‌‌‌‌‌‌‌‌​​‌​‌‌​‌‌‌‌‌‌‌‌‌​​‌‌​‌‌‌‌‌‌‌‌‌‌‌​​​‌‌‌‌‌‌‌‌‌‌‌‌‌​​‌‌‌‌​‌‌‌‌‌‌‌‌‌​​​‌​‌‌‌‌‌‌‌‌‌‌‌​​‌​‌‌‌"""

import argparse
import sys
import os
import re
import hashlib
from typing import Dict, List, Tuple, Optional, Set, Union
from enum import Enum
from pathlib import Path
import binascii

class EncodingScheme(Enum):
    # Core working schemes
    SIMPLE_8BIT = "simple_8bit"                           # ZWSP=0, ZWNJ=1, ignores incomplete bytes
    BASIC_UTF8 = "basic_utf8"                             # ZWSP=0, ZWNJ=1, 8-bit UTF-8
    BASIC_UTF8_REVERSED = "basic_utf8_reversed"           # ZWSP=1, ZWNJ=0, 8-bit UTF-8  
    BASIC_UTF16 = "basic_utf16"                           # ZWSP=1, ZWNJ=0, 16-bit UTF-16
    BASIC_UTF16_REVERSED = "basic_utf16_reversed"         # ZWSP=0, ZWNJ=1, 16-bit UTF-16
    
    # Extended schemes
    QUATERNARY_UTF8 = "quaternary_utf8"                   # 2-bit: 00=ZWSP,01=ZWNJ,10=ZWJ,11=WJ
    QUATERNARY_UTF16 = "quaternary_utf16"                 # 2-bit for UTF-16
    OCTAL_UTF8 = "octal_utf8"                             # 3-bit with 8 characters
    BINARY_DIRECTIONAL_UTF8 = "binary_directional_utf8"   # LRM=0, RLM=1
    HOMOGLYPH_BINARY_UTF8 = "homoglyph_binary_utf8"       # Homoglyph substitution
    
    # Special schemes
    ZWSP_SPACING = "zwsp_spacing"                         # ZWSP between letters, hidden message appended

class ZeroWidthEncoder:
    """
    Comprehensive encoder/decoder with ZWSP spacing support.
    """
    
    # Homoglyph mapping
    HOMOGLYPH_MAP = {
        'a': ['a', 'а'], 'A': ['A', 'А'],
        'c': ['c', 'с'], 'C': ['C', 'С'],
        'e': ['e', 'е'], 'E': ['E', 'Е'],
        'o': ['o', 'о'], 'O': ['O', 'О'],
        'p': ['p', 'р'], 'P': ['P', 'Р'],
        'x': ['x', 'х'], 'X': ['X', 'Х'],
        'y': ['y', 'у'], 'Y': ['Y', 'У'],
        'b': ['b', 'Ь'], 'B': ['B', 'В'],
        'h': ['h', 'һ'], 'H': ['H', 'Н'],
        'i': ['i', 'і'], 'I': ['I', 'І'],
        'k': ['k', 'к'], 'K': ['K', 'К'],
        'm': ['m', 'м'], 'M': ['M', 'М'],
        't': ['t', 'т'], 'T': ['T', 'Т']
    }
    
    # All scheme definitions
    SCHEMES = {
        # CORE WORKING SCHEMES
        EncodingScheme.SIMPLE_8BIT: {
            'name': 'Simple 8-bit (Your Working Decoder)',
            '0': '\u200b',  # ZWSP = 0
            '1': '\u200c',  # ZWNJ = 1
            'encoding': 'utf-8',
            'bits_per_chunk': 8,
            'description': 'EXACT simple decoder: ZWSP=0, ZWNJ=1, ignores incomplete bytes',
            'is_homoglyph': False,
            'is_zwsp_spacing': False
        },
        EncodingScheme.BASIC_UTF8: {
            'name': 'Basic UTF-8',
            '0': '\u200b',  # ZWSP = 0
            '1': '\u200c',  # ZWNJ = 1
            'encoding': 'utf-8',
            'bits_per_chunk': 8,
            'description': 'Basic UTF-8: ZWSP=0, ZWNJ=1',
            'is_homoglyph': False,
            'is_zwsp_spacing': False
        },
        EncodingScheme.BASIC_UTF8_REVERSED: {
            'name': 'Basic UTF-8 Reversed',
            '0': '\u200c',  # ZWNJ = 0
            '1': '\u200b',  # ZWSP = 1
            'encoding': 'utf-8', 
            'bits_per_chunk': 8,
            'description': 'Reversed UTF-8: ZWSP=1, ZWNJ=0',
            'is_homoglyph': False,
            'is_zwsp_spacing': False
        },
        EncodingScheme.BASIC_UTF16: {
            'name': 'Basic UTF-16',
            '0': '\u200c',  # ZWNJ = 0
            '1': '\u200b',  # ZWSP = 1  
            'encoding': 'utf-16',
            'bits_per_chunk': 16,
            'description': 'Basic UTF-16: ZWSP=1, ZWNJ=0, 16-bit chunks',
            'is_homoglyph': False,
            'is_zwsp_spacing': False
        },
        EncodingScheme.BASIC_UTF16_REVERSED: {
            'name': 'Basic UTF-16 Reversed', 
            '0': '\u200b',  # ZWSP = 0
            '1': '\u200c',  # ZWNJ = 1
            'encoding': 'utf-16',
            'bits_per_chunk': 16,
            'description': 'Reversed UTF-16: ZWSP=0, ZWNJ=1, 16-bit chunks',
            'is_homoglyph': False,
            'is_zwsp_spacing': False
        },
        
        # EXTENDED SCHEMES
        EncodingScheme.QUATERNARY_UTF8: {
            'name': 'Quaternary UTF-8 (4 symbols, 2 bits)',
            'symbol_map': {
                '00': '\u200b',  # ZWSP
                '01': '\u200c',  # ZWNJ
                '10': '\u200d',  # ZWJ
                '11': '\u2060'   # WJ
            },
            'encoding': 'utf-8',
            'bits_per_chunk': 2,
            'description': '2-bit per symbol using ZWSP, ZWNJ, ZWJ, WJ',
            'is_homoglyph': False,
            'is_zwsp_spacing': False
        },
        EncodingScheme.QUATERNARY_UTF16: {
            'name': 'Quaternary UTF-16 (4 symbols, 2 bits)',
            'symbol_map': {
                '00': '\u200b',
                '01': '\u200c',
                '10': '\u200d',
                '11': '\u2060'
            },
            'encoding': 'utf-16-le',
            'bits_per_chunk': 2,
            'description': '2-bit per symbol for UTF-16 input',
            'is_homoglyph': False,
            'is_zwsp_spacing': False
        },
        EncodingScheme.OCTAL_UTF8: {
            'name': 'Octal UTF-8 (8 symbols, 3 bits)',
            'symbol_map': {
                '000': '\u200b',  # ZWSP
                '001': '\u200c',  # ZWNJ
                '010': '\u200d',  # ZWJ
                '011': '\u2060',  # WJ
                '100': '\ufeff',  # BOM
                '101': '\u200e',  # LRM
                '110': '\u200f',  # RLM
                '111': '\u202a'   # LRE
            },
            'encoding': 'utf-8',
            'bits_per_chunk': 3,
            'description': '3-bit per symbol using 8 zero-width characters',
            'is_homoglyph': False,
            'is_zwsp_spacing': False
        },
        EncodingScheme.BINARY_DIRECTIONAL_UTF8: {
            'name': 'Binary Directional UTF-8 (LRM=0, RLM=1)',
            '0': '\u200e',  # LRM = 0
            '1': '\u200f',  # RLM = 1
            'encoding': 'utf-8',
            'bits_per_chunk': 8,
            'description': 'Binary using directional marks',
            'is_homoglyph': False,
            'is_zwsp_spacing': False
        },
        EncodingScheme.HOMOGLYPH_BINARY_UTF8: {
            'name': 'Homoglyph Binary UTF-8',
            'symbol_map': None,
            'encoding': 'utf-8',
            'bits_per_chunk': 1,
            'description': 'Binary encoding using homoglyph substitutions',
            'is_homoglyph': True,
            'is_zwsp_spacing': False
        },
        
        # ZWSP SPACING SCHEME (NEW - from your working decoder)
        EncodingScheme.ZWSP_SPACING: {
            'name': 'ZWSP Spacing Decoder',
            'description': 'Letters separated by ZWSP, hidden message appended using ZWSP spacing',
            'is_homoglyph': False,
            'is_zwsp_spacing': True
        }
    }
    
    # All zero-width characters for detection
    ALL_ZERO_WIDTH_CHARS = {
        '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060', 
        '\u180e', '\u200e', '\u200f', '\u202a', '\u202b',
        '\u202c', '\u202d', '\u202e', '\u2061', '\u2062',
        '\u2063', '\u2064'
    }
    
    def __init__(self, scheme: EncodingScheme = EncodingScheme.SIMPLE_8BIT):
        self.scheme = scheme
        self.config = self.SCHEMES[scheme]
    
    def encode(self, text: str, carrier: Optional[str] = None) -> str:
        """Encode text using the specified scheme."""
        if self.config['is_homoglyph']:
            return self._encode_homoglyph(text, carrier)
        elif self.config['is_zwsp_spacing']:
            return self._encode_zwsp_spacing(text, carrier)
        elif self.scheme in [EncodingScheme.QUATERNARY_UTF8, EncodingScheme.QUATERNARY_UTF16, 
                            EncodingScheme.OCTAL_UTF8]:
            return self._encode_extended(text)
        else:
            encoded = self._encode_basic(text)
            if carrier:
                return self._embed_in_carrier(encoded, carrier)
            return encoded
    
    def _encode_basic(self, text: str) -> str:
        """Encode using basic binary schemes."""
        if self.config['encoding'].startswith('utf-16'):
            return self._encode_utf16(text)
        else:
            return self._encode_utf8(text)
    
    def _encode_utf8(self, text: str) -> str:
        """Encode text as UTF-8 bytes."""
        binary_data = ''.join(format(byte, '08b') for byte in text.encode('utf-8'))
        return binary_data.replace('0', self.config['0']).replace('1', self.config['1'])
    
    def _encode_utf16(self, text: str) -> str:
        """Encode text as UTF-16 code units."""
        text_bytes = text.encode('utf-16-le')  # Use little endian without BOM
        binary_data = ''
        for i in range(0, len(text_bytes), 2):
            if i + 1 < len(text_bytes):
                code_unit = (text_bytes[i + 1] << 8) | text_bytes[i]  # Little endian
                binary_data += format(code_unit, '016b')
        return binary_data.replace('0', self.config['0']).replace('1', self.config['1'])
    
    def _encode_extended(self, text: str) -> str:
        """Encode using extended schemes (quaternary, octal)."""
        # Encode to bytes
        if self.config['encoding'].startswith('utf-16'):
            bytes_data = text.encode('utf-16-le')
        else:
            bytes_data = text.encode('utf-8')
        
        # Convert to binary
        binary = ''.join(format(byte, '08b') for byte in bytes_data)
        
        # Group bits and map to symbols
        bit_group_size = self.config['bits_per_chunk']
        mapped = ''
        
        for i in range(0, len(binary), bit_group_size):
            group = binary[i:i + bit_group_size]
            if len(group) == bit_group_size and group in self.config['symbol_map']:
                mapped += self.config['symbol_map'][group]
        
        return mapped
    
    def _encode_homoglyph(self, text: str, carrier: Optional[str]) -> str:
        """Encode using homoglyph substitution."""
        if carrier is None:
            raise ValueError("Carrier text required for homoglyph encoding")
        
        # Convert text to binary
        bytes_data = text.encode('utf-8')
        binary = ''.join(format(byte, '08b') for byte in bytes_data)
        
        # Replace characters in carrier with homoglyphs based on binary
        bit_idx = 0
        output = []
        
        for char in carrier:
            if char in self.HOMOGLYPH_MAP and bit_idx < len(binary):
                bit = binary[bit_idx]
                replacement = self.HOMOGLYPH_MAP[char][int(bit)]
                output.append(replacement)
                bit_idx += 1
            else:
                output.append(char)
        
        if bit_idx < len(binary):
            raise ValueError("Carrier text too short for the message")
        
        return ''.join(output)
    
    def _encode_zwsp_spacing(self, text: str, carrier: Optional[str]) -> str:
        """Encode using ZWSP spacing between letters."""
        if carrier:
            # Insert ZWSP between each character of carrier for spacing
            spaced_carrier = '\u200b'.join(carrier)
            # Append the hidden message
            return spaced_carrier + text
        else:
            # Just insert ZWSP between each character
            return '\u200b'.join(text)
    
    def _embed_in_carrier(self, encoded: str, carrier: str) -> str:
        """Embed zero-width encoded text into carrier text."""
        if not encoded:
            return carrier
        
        # Simple embedding: append to end (most reliable)
        return carrier + encoded
    
    def decode(self, encoded_text: str) -> str:
        """Decode encoded text back to original."""
        if self.config['is_homoglyph']:
            return self._decode_homoglyph(encoded_text)
        elif self.config['is_zwsp_spacing']:
            return self._decode_zwsp_spacing(encoded_text)
        elif self.scheme == EncodingScheme.SIMPLE_8BIT:
            return self._decode_simple_8bit(encoded_text)
        elif self.scheme in [EncodingScheme.BASIC_UTF8, EncodingScheme.BASIC_UTF8_REVERSED]:
            return self._decode_basic_utf8(encoded_text)
        elif self.scheme in [EncodingScheme.BASIC_UTF16, EncodingScheme.BASIC_UTF16_REVERSED]:
            return self._decode_basic_utf16(encoded_text)
        elif self.scheme in [EncodingScheme.QUATERNARY_UTF8, EncodingScheme.QUATERNARY_UTF16,
                            EncodingScheme.OCTAL_UTF8, EncodingScheme.BINARY_DIRECTIONAL_UTF8]:
            return self._decode_extended(encoded_text)
        else:
            return self._decode_basic_utf8(encoded_text)  # Fallback
    
    def _decode_simple_8bit(self, encoded_text: str) -> str:
        """
        EXACT replica of your working simple 8-bit decoder.
        ZWSP=0, ZWNJ=1, ignores incomplete bytes.
        """
        # Map zero-width characters back to binary - EXACTLY as your decoder does
        binary_data = encoded_text.replace('\u200b', '0').replace('\u200c', '1')
        
        # Split into 8-bit chunks - EXACTLY as your decoder does
        bytes_list = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
        
        # Convert to characters (ignore incomplete bytes) - EXACTLY as your decoder does
        decoded_bytes = []
        for b in bytes_list:
            if len(b) == 8:
                try:
                    decoded_bytes.append(int(b, 2))
                except ValueError:
                    continue
        
        return bytes(decoded_bytes).decode('utf-8', errors='ignore')
    
    def _decode_basic_utf8(self, encoded_text: str) -> str:
        """Decode basic UTF-8 schemes."""
        zero_width_chars = {self.config['0'], self.config['1']}
        filtered = ''.join(c for c in encoded_text if c in zero_width_chars)
        
        if not filtered:
            return ""
        
        # Map to binary
        binary_data = "".join("1" if c == self.config['1'] else "0" for c in filtered)
        
        # Ensure length is multiple of 8
        remainder = len(binary_data) % 8
        if remainder != 0:
            binary_data = binary_data[:len(binary_data) - remainder]
        
        # Convert to bytes and decode
        byte_data = bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))
        return byte_data.decode('utf-8', errors='ignore')
    
    def _decode_basic_utf16(self, encoded_text: str) -> str:
        """Decode basic UTF-16 schemes with proper surrogate handling."""
        zero_width_chars = {self.config['0'], self.config['1']}
        filtered = ''.join(c for c in encoded_text if c in zero_width_chars)
        
        if not filtered:
            return ""
        
        # Map to binary
        binary_data = "".join("1" if c == self.config['1'] else "0" for c in filtered)
        
        # Ensure length is multiple of 16
        remainder = len(binary_data) % 16
        if remainder != 0:
            binary_data = binary_data[:len(binary_data) - remainder]
        
        # Convert to UTF-16 code units
        chars = []
        for i in range(0, len(binary_data), 16):
            if i + 16 <= len(binary_data):
                chunk = binary_data[i:i+16]
                code_point = int(chunk, 2)
                
                # Handle surrogates properly
                if 0xD800 <= code_point <= 0xDFFF:
                    continue  # Skip surrogate characters
                try:
                    chars.append(chr(code_point))
                except (ValueError, OverflowError):
                    continue
        
        decoded_text = "".join(chars)
        
        # Clean up any remaining encoding issues
        try:
            decoded_text.encode('utf-8')
            return decoded_text
        except UnicodeEncodeError:
            cleaned_text = ""
            for char in decoded_text:
                try:
                    char.encode('utf-8')
                    cleaned_text += char
                except UnicodeEncodeError:
                    continue
            return cleaned_text
    
    def _decode_extended(self, encoded_text: str) -> str:
        """Decode extended schemes (quaternary, octal, directional)."""
        # Filter only relevant characters
        if 'symbol_map' in self.config:
            used_chars = set(self.config['symbol_map'].values())
        else:
            used_chars = {self.config['0'], self.config['1']}
        
        filtered = ''.join(c for c in encoded_text if c in used_chars)
        
        if not filtered:
            return ""
        
        # Reverse mapping
        if 'symbol_map' in self.config:
            reverse_map = {v: k for k, v in self.config['symbol_map'].items()}
            binary = ''.join(reverse_map.get(c, '') for c in filtered)
        else:
            binary = "".join("1" if c == self.config['1'] else "0" for c in filtered)
        
        # Convert binary to text
        return self._binary_to_text(binary, self.config['encoding'])
    
    def _decode_homoglyph(self, encoded_text: str) -> str:
        """Decode homoglyph encoded text."""
        # Build reverse mapping
        reverse_map = {}
        for char, variants in self.HOMOGLYPH_MAP.items():
            if len(variants) >= 2:
                reverse_map[variants[0]] = '0'  # Original = 0
                reverse_map[variants[1]] = '1'  # Homoglyph = 1
        
        # Extract binary from homoglyph substitutions
        binary = ''
        for char in encoded_text:
            if char in reverse_map:
                binary += reverse_map[char]
        
        return self._binary_to_text(binary, 'utf-8')
    
    def _decode_zwsp_spacing(self, encoded_text: str) -> str:
        """
        EXACT replica of your working ZWSP spacing decoder.
        Letters separated by ZWSP, hidden message appended using ZWSP spacing.
        """
        # Split by ZWSP
        parts = encoded_text.split('\u200b')
        
        # Remove empty strings caused by consecutive ZWSP
        letters = [p for p in parts if p]
        
        # Join letters back - this gives us the hidden message
        decoded_text = "".join(letters)
        
        return decoded_text
    
    def _binary_to_text(self, binary: str, encoding: str) -> str:
        """Convert binary string to text with proper encoding."""
        # Ensure binary length is multiple of 8
        remainder = len(binary) % 8
        if remainder != 0:
            binary = binary[:-remainder]
        
        if not binary:
            return ""
        
        try:
            bytes_data = bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
            
            if encoding.startswith('utf-16'):
                # Handle UTF-16 decoding
                decoded_text = ""
                for i in range(0, len(bytes_data), 2):
                    if i + 1 < len(bytes_data):
                        code_unit = (bytes_data[i + 1] << 8) | bytes_data[i]
                        if 0xD800 <= code_unit <= 0xDFFF:
                            continue  # Skip surrogates
                        try:
                            decoded_text += chr(code_unit)
                        except (ValueError, OverflowError):
                            continue
                return decoded_text
            else:
                return bytes_data.decode('utf-8', errors='ignore')
                
        except (ValueError, UnicodeDecodeError):
            return ""

class ZeroWidthDetector:
    """
    Comprehensive detector that includes ZWSP spacing detection.
    """
    
    @staticmethod
    def detect_scheme(text: str) -> Optional[Tuple[EncodingScheme, float, str]]:
        """
        Detect encoding scheme by trying all schemes, prioritizing working ones first.
        """
        # Priority order: working schemes first, then extended schemes, then special schemes
        priority_schemes = [
            EncodingScheme.SIMPLE_8BIT,      # Your exact working decoder
            EncodingScheme.BASIC_UTF8,       # Basic UTF-8
            EncodingScheme.BASIC_UTF16,      # Basic UTF-16  
            EncodingScheme.BASIC_UTF8_REVERSED,
            EncodingScheme.BASIC_UTF16_REVERSED,
            EncodingScheme.QUATERNARY_UTF8,  # Extended schemes
            EncodingScheme.QUATERNARY_UTF16,
            EncodingScheme.OCTAL_UTF8,
            EncodingScheme.BINARY_DIRECTIONAL_UTF8,
            EncodingScheme.HOMOGLYPH_BINARY_UTF8,
            EncodingScheme.ZWSP_SPACING      # Special ZWSP spacing decoder
        ]
        
        best_scheme = None
        best_confidence = 0.0
        best_result = ""
        best_reason = ""
        
        for scheme in priority_schemes:
            try:
                encoder = ZeroWidthEncoder(scheme)
                decoded = encoder.decode(text)
                
                if decoded and len(decoded) > 0:
                    confidence, reason = ZeroWidthDetector._evaluate_decoding(decoded, text, scheme)
                    
                    # Boost confidence for working schemes
                    if scheme in [EncodingScheme.SIMPLE_8BIT, EncodingScheme.ZWSP_SPACING] and confidence > 0.3:
                        confidence = min(confidence + 0.2, 1.0)
                        reason += " (priority working scheme)"
                    
                    if confidence > best_confidence:
                        best_scheme = scheme
                        best_confidence = confidence
                        best_result = decoded
                        best_reason = reason
                        
            except Exception:
                continue
        
        if best_scheme and best_confidence > 0.3:
            return (best_scheme, best_confidence, best_reason)
        
        return None
    
    @staticmethod
    def _evaluate_decoding(decoded: str, original: str, scheme: EncodingScheme) -> Tuple[float, str]:
        """Evaluate the quality of a decoding attempt."""
        if not decoded or len(decoded) < 2:
            return 0.0, "Too short or empty"
        
        # For ZWSP spacing, we have different evaluation criteria
        if scheme == EncodingScheme.ZWSP_SPACING:
            # Check if the result looks like meaningful text
            if len(decoded) > 10 and any(c.isalpha() for c in decoded):
                # Count printable characters
                printable_count = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t')
                printable_ratio = printable_count / len(decoded)
                
                if printable_ratio > 0.8:
                    return 0.9, "ZWSP spacing detected with high quality text"
                elif printable_ratio > 0.6:
                    return 0.7, "ZWSP spacing detected with reasonable text"
                else:
                    return 0.4, "ZWSP spacing detected but low text quality"
            return 0.3, "ZWSP spacing pattern detected"
        
        # Standard evaluation for other schemes
        printable_count = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t')
        printable_ratio = printable_count / len(decoded)
        
        # Common patterns
        common_patterns = [
            ' the ', ' and ', ' is ', ' to ', ' of ', ' in ', ' a ', ' that ',
            ' with ', ' for ', ' on ', ' are ', ' this ', ' from ', ' have ', ' was ',
            ' you ', ' your ', ' that ', ' with ', ' they ', ' their ', ' which '
        ]
        lower_decoded = decoded.lower()
        pattern_count = sum(1 for pattern in common_patterns if pattern in lower_decoded)
        pattern_score = min(pattern_count * 0.1, 0.5)
        
        # CTF flag patterns
        flag_patterns = [
            r'flag\{[^}]+\}', r'ctf\{[^}]+\}', r'htb\{[^}]+\}', 
            r'picoctf\{[^}]+\}', r'cyber\{[^}]+\}'
        ]
        flag_score = 0.0
        for pattern in flag_patterns:
            if re.search(pattern, decoded, re.IGNORECASE):
                flag_score = 0.4
                break
        
        # Combined score
        score = (printable_ratio * 0.5) + pattern_score + flag_score
        
        reason_parts = []
        if printable_ratio > 0.8:
            reason_parts.append("high printable ratio")
        if pattern_count > 2:
            reason_parts.append("common patterns")
        if flag_score > 0:
            reason_parts.append("CTF flag")
        
        reason = "Good decoding: " + ", ".join(reason_parts) if reason_parts else "Moderate confidence"
        
        return min(score, 1.0), reason

def analyze_file_content(text: str) -> Dict:
    """Comprehensive analysis of zero-width and homoglyph content."""
    zero_width_defs = {
        'ZWSP': '\u200b',
        'ZWNJ': '\u200c', 
        'ZWJ': '\u200d',
        'WJ': '\u2060',
        'BOM': '\ufeff',
        'LRM': '\u200e',
        'RLM': '\u200f',
        'LRE': '\u202a',
        'RLE': '\u202b'
    }
    
    analysis = {
        'total_chars': len(text),
        'zero_width_chars': {name: text.count(char) for name, char in zero_width_defs.items()},
        'total_zero_width': 0,
        'homoglyph_chars': {},
        'total_homoglyph': 0,
        'likely_schemes': []
    }
    
    # Calculate zero-width totals
    analysis['total_zero_width'] = sum(analysis['zero_width_chars'].values())
    
    # Calculate homoglyph presence
    homoglyph_variants = set()
    for variants in ZeroWidthEncoder.HOMOGLYPH_MAP.values():
        homoglyph_variants.update(variants[1:])  # Exclude original characters
    
    analysis['homoglyph_chars'] = {c: text.count(c) for c in homoglyph_variants if text.count(c) > 0}
    analysis['total_homoglyph'] = sum(analysis['homoglyph_chars'].values())
    
    # Determine likely schemes based on character distribution
    zwsp_count = analysis['zero_width_chars']['ZWSP']
    zwnj_count = analysis['zero_width_chars']['ZWNJ']
    total_basic = zwsp_count + zwnj_count
    
    # Check for ZWSP spacing pattern (many ZWSP, few or no ZWNJ)
    if zwsp_count > 0 and zwnj_count == 0:
        # Check if ZWSP are evenly distributed (spacing pattern)
        if zwsp_count > len(text) * 0.1:  # More than 10% ZWSP
            analysis['likely_schemes'].append("ZWSP_SPACING (letters separated by ZWSP)")
    
    if total_basic > 0:
        if zwsp_count > zwnj_count:
            analysis['likely_schemes'].append("BASIC_UTF16 (ZWSP=1, ZWNJ=0)")
            analysis['likely_schemes'].append("BASIC_UTF8_REVERSED (ZWSP=1, ZWNJ=0)")
        else:
            analysis['likely_schemes'].append("SIMPLE_8BIT (ZWSP=0, ZWNJ=1)")
            analysis['likely_schemes'].append("BASIC_UTF8 (ZWSP=0, ZWNJ=1)")
    
    if analysis['zero_width_chars']['ZWJ'] > 0 or analysis['zero_width_chars']['WJ'] > 0:
        analysis['likely_schemes'].append("QUATERNARY schemes")
    
    if analysis['total_zero_width'] >= 8:
        analysis['likely_schemes'].append("OCTAL schemes")
    
    if analysis['zero_width_chars']['LRM'] > 0 or analysis['zero_width_chars']['RLM'] > 0:
        analysis['likely_schemes'].append("DIRECTIONAL schemes")
    
    if analysis['total_homoglyph'] > 0:
        analysis['likely_schemes'].append("HOMOGLYPH schemes")
    
    return analysis

def read_input(input_arg: str) -> str:
    """Read input from file or stdin."""
    if input_arg == '-':
        return sys.stdin.read()
    with open(input_arg, 'r', encoding='utf-8') as f:
        return f.read()

def write_output(output_arg: Optional[str], content: str):
    """Write output to file or stdout."""
    if output_arg == '-' or output_arg is None:
        print(content, end='')
    else:
        with open(output_arg, 'w', encoding='utf-8') as f:
            f.write(content)

def main():
    parser = argparse.ArgumentParser(
        description='ULTIMATE ZERO-WIDTH STEGANOGRAPHY TOOL - COMPLETE VERSION',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Examples:
  # Auto-detect and decode (now includes ZWSP spacing)
  {sys.argv[0]} decode -i zero_width_repo_only.txt
  
  # Use specific ZWSP spacing decoder
  {sys.argv[0]} decode -i zero_width_repo_only.txt --scheme zwsp_spacing
  
  # Use your exact working decoder
  {sys.argv[0]} decode -i encoded.txt --scheme simple_8bit
  
  # Encode with ZWSP spacing
  {sys.argv[0]} encode "hidden message" -o output.txt --scheme zwsp_spacing --carrier carrier.txt

Priority Schemes (auto-detection order):
  1. simple_8bit      - Your exact working decoder (ZWSP=0, ZWNJ=1)
  2. basic_utf8       - Basic UTF-8 encoding
  3. basic_utf16      - Basic UTF-16 encoding
  4. zwsp_spacing     - ZWSP between letters, hidden message appended
  5. Extended schemes - Quaternary, Octal, Directional, Homoglyph

Full Scheme List:
{chr(10).join(f"  {s.value:<25} - {ZeroWidthEncoder.SCHEMES[s]['description']}" for s in EncodingScheme)}
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Encode command
    encode_parser = subparsers.add_parser('encode', help='Encode text or file')
    encode_parser.add_argument('text', nargs='?', help='Text to encode (or use --input)')
    encode_parser.add_argument('-i', '--input', help='Input file or - for stdin')
    encode_parser.add_argument('-o', '--output', help='Output file or - for stdout')
    encode_parser.add_argument('-s', '--scheme', 
                              choices=[s.value for s in EncodingScheme],
                              default='simple_8bit',
                              help='Encoding scheme to use')
    encode_parser.add_argument('--carrier', help='Carrier text file for embedding')
    
    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Decode zero-width text')
    decode_parser.add_argument('-i', '--input', required=True, help='Input file or - for stdin')
    decode_parser.add_argument('-o', '--output', help='Output file or - for stdout')
    decode_parser.add_argument('-s', '--scheme', 
                              choices=[s.value for s in EncodingScheme],
                              help='Encoding scheme (auto-detect if omitted)')
    decode_parser.add_argument('--force', action='store_true', 
                              help='Force decoding even with low confidence')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze for steganography content')
    analyze_parser.add_argument('-i', '--input', required=True, help='Input file or - for stdin')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == 'encode':
            # Get input text
            if args.text:
                text = args.text
            elif args.input:
                text = read_input(args.input)
            else:
                encode_parser.error("Either provide text argument or use --input")
            
            # Get carrier if specified
            carrier = None
            if args.carrier:
                carrier = read_input(args.carrier)
            
            encoder = ZeroWidthEncoder(EncodingScheme(args.scheme))
            encoded = encoder.encode(text, carrier)
            
            write_output(args.output, encoded)
            
            print(f"SUCCESS: Encoded {len(text)} characters using {encoder.config['name']}")
            if carrier:
                print(f"Embedded in carrier text ({len(carrier)} chars)")
            else:
                print(f"Output contains {len(encoded)} characters")
        
        elif args.command == 'decode':
            encoded_text = read_input(args.input)
            
            if args.scheme:
                scheme = EncodingScheme(args.scheme)
                encoder = ZeroWidthEncoder(scheme)
                print(f"Using specified scheme: {encoder.config['name']}")
            else:
                print("Auto-detecting encoding scheme (priority: working schemes first)...")
                detection_result = ZeroWidthDetector.detect_scheme(encoded_text)
                if not detection_result:
                    if args.force:
                        print("No scheme detected with high confidence, forcing SIMPLE_8BIT...")
                        scheme = EncodingScheme.SIMPLE_8BIT
                    else:
                        print("ERROR: Could not auto-detect encoding scheme with confidence.")
                        print("Use --scheme to specify manually or --force to try anyway.")
                        
                        # Show analysis to help user choose
                        analysis = analyze_file_content(encoded_text)
                        if analysis['total_zero_width'] > 0 or analysis['total_homoglyph'] > 0:
                            print("\nCONTENT ANALYSIS:")
                            if analysis['total_zero_width'] > 0:
                                print(f"Zero-width characters: {analysis['total_zero_width']}")
                                for name, count in analysis['zero_width_chars'].items():
                                    if count > 0:
                                        print(f"  {name}: {count}")
                            
                            if analysis['total_homoglyph'] > 0:
                                print(f"Homoglyph characters: {analysis['total_homoglyph']}")
                            
                            if analysis['likely_schemes']:
                                print("\nSUGGESTED SCHEMES (try in order):")
                                for scheme_desc in analysis['likely_schemes']:
                                    print(f"  {scheme_desc}")
                        sys.exit(1)
                else:
                    scheme, confidence, reason = detection_result
                    encoder = ZeroWidthEncoder(scheme)
                    print(f"SUCCESS: Auto-detected: {encoder.config['name']}")
                    print(f"Confidence: {confidence:.2f} - {reason}")
                    
                    if confidence < 0.5 and not args.force:
                        print("WARNING: Low confidence detection. Use --force to proceed.")
                        sys.exit(1)
            
            # Perform decoding
            decoded = encoder.decode(encoded_text)
            
            if not decoded:
                print("WARNING: No decodable content found.")
            
            write_output(args.output, decoded)
            
            if args.output is None:
                print("\n" + "="*60)
                print("DECODED MESSAGE:")
                print("="*60)
                print(decoded)
                if not decoded.endswith('\n'):
                    print()  # Ensure newline
                print("="*60)
            else:
                print(f"SUCCESS: Decoded to {args.output}")
        
        elif args.command == 'analyze':
            text = read_input(args.input)
            analysis = analyze_file_content(text)
            
            print(f"ANALYSIS RESULTS:")
            print(f"Total characters: {analysis['total_chars']}")
            
            if analysis['total_zero_width'] > 0:
                print(f"Zero-width characters: {analysis['total_zero_width']}")
                print("Breakdown:")
                for name, count in analysis['zero_width_chars'].items():
                    if count > 0:
                        print(f"  {name}: {count}")
            
            if analysis['total_homoglyph'] > 0:
                print(f"Homoglyph characters: {analysis['total_homoglyph']}")
            
            if analysis['likely_schemes']:
                print("\nLIKELY ENCODING SCHEMES:")
                for scheme in analysis['likely_schemes']:
                    print(f"  {scheme}")
            
            # Try auto-detection and decoding
            if analysis['total_zero_width'] > 0 or analysis['total_homoglyph'] > 0:
                print("\nATTEMPTING AUTO-DECODING...")
                detection_result = ZeroWidthDetector.detect_scheme(text)
                if detection_result:
                    scheme, confidence, reason = detection_result
                    encoder = ZeroWidthEncoder(scheme)
                    decoded = encoder.decode(text)
                    print(f"SUCCESS: Detected {encoder.config['name']} (confidence: {confidence:.2f})")
                    print(f"Decoded sample (first 200 chars):")
                    sample = decoded[:200]
                    if len(decoded) > 200:
                        sample += "..."
                    print(f"  {sample}")
                else:
                    print("No scheme could be automatically detected with confidence.")
            
            if analysis['total_zero_width'] == 0 and analysis['total_homoglyph'] == 0:
                print("\nNo zero-width or homoglyph steganography detected.")
    
    except FileNotFoundError as e:
        print(f"ERROR: File not found - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
