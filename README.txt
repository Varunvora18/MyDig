All the python files have been tested for python 3.7 and above.

The following libraries will have to be installed to run the following py files:
-dnspython
-cryptography


--------------------------------------------------------------------------------------------------------------------------------------------
For execution of code it is preferrerable to run it using Visual Studio Code. You can also run it using following commands from the command line (Tested on a Mac).

For Part A:

python ./mydig.py google.com A
python ./mydig.py google.com NS
python ./mydig.py google.com MX

The output is also stored in mydig_output.txt

For Part B:
python ./dnssec.py verisigninc.com

One can refer the DNSSEC_Implementation.pdf to better understand the implementation
-------------------------------------------------------------------------------------------------------------------------------------------