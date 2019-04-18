## About
This tool can be used to decompress an [Aqualead](http://aqualead.co.jp/) LZSS file. These files are recognizable by their header magic "ALLZ". Aqualead's [ALLZ compression](http://fw.aqualead.co.jp/Document/Aqualead/Tool/ALCompress.html) is described in their documentation as a modified version of LZSS with some of their own tweaks and optimizations.  

For the record, this is just one format [out of 15-ish](../master/aqualead_types.h) provided by the Aqualead framework. I am only aware of small handful of games to make use of these formats, though I'm sure there are others. To name a few, Groove Coaster for Steam, Pandora's Tower (Wii), and Zanki Zero: Last Beginning.  

## Usage
```text
  Aqualead_LZSS.exe [INPUT_FILE] [OUTPUT_FILE]
```  

The `[OUTPUT_FILE]` name is optional. You can also drag'n'drop an ALLZ compressed file onto the executable and it'll do its thing automatically. If you don't specify the output file's path and name, it will by default output to a file in your calling directory matching this pattern: `out_FILE.ext`.  
**IMPORTANT:** This program makes no promise of knowing the exact end of your ALLZ file. If your ALLZ compressed file is longer than it should be and/or contains more than just the lone ALLZ file, then decompression **might** fail.  

## Building
This is a qmake project. The shortest solution **if you already have** [Qt Creator](https://www.qt.io/download), is to Open the `.pro` file in Qt, select your kit and build the project.  
I've only tested this in Windows with MSVC2017 and MinGW 32-bit GCC (but I don't recommend using GCC unless you're on Linux).  
