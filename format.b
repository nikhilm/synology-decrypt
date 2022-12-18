#lang binfmt

format = magic magic-hash dict+ ;
magic = '_' '_' 'C' 'L' 'O' 'U' 'D' 'S' 'Y' 'N' 'C' '_' 'E' 'N' 'C' '_' '_';
magic-hash = 'd' '8' 'd' '6' 'b' 'a' '7' 'b' '9' 'd' 'f' '0' '2' 'e' 'f' '3' '9' 'a' '3' '3' 'e' 'f' '9' '1' '2' 'a' '9' '1' 'd' 'c' '5' '6' ;
dict = 0x42 dict-entry* 0x40;
dict-entry = key value;
key = string;
value = string | bytes | int | dict ;
string = 0x10 string-rest;
bytes = 0x11 bytes-rest;
int = 0x01 int-rest;
int-rest = u8 u8{u8_1};
string-rest = length u8{length_1};
bytes-rest = length u8{length_1};
length = u16be;