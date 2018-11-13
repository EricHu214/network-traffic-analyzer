import os
import json
import pandas as pd







file_orig = open("packet export.json", "r")


max_num_packets = 50000
min_num_packets = 1



brackets = 0
counter = 0
packet_count = 0
file_num = 0

file_content = "[\n"

file = open("export" + str(file_num) + ".json", "w")

for line in file_orig:
    if line.find("{") != -1:
        brackets += 1

    elif line.find("}") != -1:
        brackets -= 1

    if line.find("]") == -1 and line.find("[") == -1 and not (file_content.strip() == "[" and line.strip() == ","):
        file_content += line


    if brackets == 0 and counter != 0:
        packet_count += 1

    if packet_count == max_num_packets:
        file_content += "]"
        file.write(file_content)
        file_content = "[\n"
        packet_count = 0
        counter = 0
        file_num += 1
        file = open("export" + str(file_num) + ".json", "w")

    counter += 1


file.write(file_content)
