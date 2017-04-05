#!/usr/bin/env bash

# compile & clean
cd src
javac *.java
jar cfev logAnalyzer.jar LogAnalyzer *.class
rm *.class
cd ..
echo ""

mkdir log_output

# run
# single input
time java -jar src/logAnalyzer.jar log_input/log.txt

# multiple input
# time java -jar src/logAnalyzer.jar log_input/log.1.txt log_input/log.2.txt


# http://askubuntu.com/questions/464755/how-to-install-openjdk-8-on-14-04-lts