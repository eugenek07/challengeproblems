def read_file_to_byte_list(filename):
    with open(filename, "rb") as f:
        return list(f.read())

def write_byte_list_to_file(byte_list, filename):
    with open(filename, "wb") as f:
        f.write(bytes(byte_list))

def test_files_equal(file1, file2):
    with open(file1, "rb") as f1, open(file2, "rb") as f2:
        return f1.read() == f2.read()

def main():
    input_file = "test_input.txt"
    output_file = "test_output.txt"
    byte_list = read_file_to_byte_list(input_file)
    write_byte_list_to_file(byte_list, output_file)
    if test_files_equal(input_file, output_file):
        print("Success")
    else:
        print("Error: Files do not match.")

if __name__ == "__main__":
    main()
