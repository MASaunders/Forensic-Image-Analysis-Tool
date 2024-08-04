import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import pytsk3
import os
import re

# NOTE: This is the most complete version of this code, make a copy and continue work from that point

class ForensicAnalysisTool:
    def __init__(self):
        self.evidence_file = None
        self.file_system = None

    def open_evidence_file(self, file_path):
        try:
            self.evidence_file = pytsk3.Img_Info(file_path)
            return True
        except Exception as e:
            self.show_error_popup(f"Error opening evidence file: {str(e)}")
            return False

    def list_partitions(self):
        if self.evidence_file:
            try:
                partition_table = pytsk3.Volume_Info(self.evidence_file)
                return [f"{partition.desc.decode('ascii')}  |  Start = {partition.start}  |  Bytes = {partition.len}" for partition in partition_table]
            except Exception as e:
                self.show_error_popup(f"Error listing partitions: {str(e)}")

    def open_partition(self, partition_num):
        if self.evidence_file:
            try:
                partition_table = pytsk3.Volume_Info(self.evidence_file)
                partition = list(partition_table)[partition_num - 1]
                offset = partition.start * 512  # Default sector size: 512 

                if offset >= self.evidence_file.get_size():
                    self.show_error_popup("Invalid offset: Offset exceeds the size of the evidence file.")
                    return False

                try:
                    self.file_system = pytsk3.FS_Info(self.evidence_file, offset)
                    return True
                except Exception as e:
                    self.show_error_popup(f"Error opening filesystem!") # {str(e)} > Gives a detailed error, dev purposes only

            except (ValueError, IndexError) as e:
                self.show_error_popup(f"Error opening partition: {str(e)}")
        return False

    def list_files_in_directory(self, dir_path):
        if self.file_system:
            try:
                directory = self.file_system.open_dir(dir_path)
                return [entry.info.name.name.decode('utf-8') for entry in directory]
            except Exception as e:
                self.show_error_popup(f"Error listing files: {str(e)}")

    def display_file_details(self, file_path):
        if self.file_system:
            try:
                file_entry = self.file_system.open(file_path)
                file_info = file_entry.info
                details = f"File Path: {file_path}\n"

                if hasattr(file_entry, "size"):
                    details += f"File Size: {file_entry.size}\n"
                else:
                    details += f"File Size: {file_info.meta.size}\n"

                details += f"Creation Time: {file_info.meta.crtime}\n"
                details += f"Modification Time: {file_info.meta.mtime}\n"
                return details

            except Exception as e:
                self.show_error_popup(f"Error displaying file details: {str(e)}")
    def search_unallocated_space(self, regex_pattern):
        if self.file_system:
            try:
                unallocated_space = self.get_unallocated_space_content()
                matches = re.findall(regex_pattern, unallocated_space)
                return matches
            except Exception as e:
                self.show_error_popup(f"Error searching unallocated space: {str(e)}")

    def get_unallocated_space_content(self):
        if self.file_system:
            try:
                # Assuming unallocated space starts at offset 0
                unallocated_offset = 0
                unallocated_size = self.evidence_file.get_size() - unallocated_offset

                # Read unallocated space content
                unallocated_data = self.evidence_file.read_random(unallocated_offset, unallocated_size)
                return unallocated_data.decode('utf-8', errors='ignore')  # Use utf-8 and ignore errors for decoding
            except Exception as e:
                self.show_error_popup(f"Error reading unallocated space content: {str(e)}")
        return ""

    def show_filesystem_info(self):
        if self.evidence_file:
            try:
                size = self.evidence_file.get_size()
                total_sectors = size / 512

                volume_info = pytsk3.Volume_Info(self.evidence_file)
                block_size = volume_info.info.block_size
                partition_table_type = volume_info.info.vstype

                size_label_text = f"The image file is {size} bytes in size"
                sectors_label_text = f"Total number of sectors in image is {total_sectors}"
                block_size_label_text = f'Size of the block is set to {block_size}'

                partition_type_text = "Partition table is MBR" if partition_table_type == pytsk3.TSK_VS_TYPE_DOS \
                    else "Partition table is GPT" if partition_table_type == pytsk3.TSK_VS_TYPE_GPT \
                    else "Unknown partition table type"

                return size_label_text, sectors_label_text, block_size_label_text, partition_type_text

            except Exception as e:
                self.show_error_popup(f"Error getting filesystem information: {str(e)}")

    def show_error_popup(self, error_message):
        messagebox.showerror("Error", error_message)

    

class GUI(tk.Tk):
    def __init__(self, base_init):
        super().__init__()
        self.title("The Forensic Analysis Tool")
        self.base_init = base_init

        # Create a main frame
        self.main_frame = tk.Frame(self)
        self.main_frame.pack(padx=10, pady=10)

        # BUTTONS & INPUT
        # 
        self.open_evidence_button = tk.Button(self.main_frame, text="Open Evidence File", command=self.open_evidence_file_gui, width=20, height=2)
        self.open_evidence_button.grid(row=0, column=0, pady=5, padx=5)
        # 
        self.list_partitions_button = tk.Button(self.main_frame, text="List Partitions", command=self.list_partitions_gui, width=20, height=2)
        self.list_partitions_button.grid(row=0, column=1, pady=5, padx=5)
        # 
        self.partition_entry_label = tk.Label(self.main_frame, text="Enter Partition Number:")
        self.partition_entry_label.grid(row=1, column=0, pady=5, padx=5)
        # 
        self.partition_entry = tk.Entry(self.main_frame)
        self.partition_entry.grid(row=1, column=1, pady=5, padx=5)
        # 
        self.open_partition_button = tk.Button(self.main_frame, text="Open Partition", command=self.open_partition_gui, width=20, height=2)
        self.open_partition_button.grid(row=1, column=2, pady=5, padx=5)
        # 
        self.directory_entry_label = tk.Label(self.main_frame, text="Enter Directory Path:")
        self.directory_entry_label.grid(row=2, column=0, pady=5, padx=5)
        # 
        self.directory_entry = tk.Entry(self.main_frame)
        self.directory_entry.grid(row=2, column=1, pady=5, padx=5)
        # 
        self.list_files_button = tk.Button(self.main_frame, text="List Files", command=self.list_files_gui, width=20, height=2)
        self.list_files_button.grid(row=2, column=2, pady=5, padx=5)
        # 
        self.file_path_entry_label = tk.Label(self.main_frame, text="Enter File Path:")
        self.file_path_entry_label.grid(row=3, column=0, pady=5, padx=5)
        # 
        self.file_path_entry = tk.Entry(self.main_frame)
        self.file_path_entry.grid(row=3, column=1, pady=5, padx=5)
        # 
        self.display_file_details_button = tk.Button(self.main_frame, text="Display File Details", command=self.display_file_details_command, width=20, height=2)
        self.display_file_details_button.grid(row=3, column=2, pady=5, padx=5)

        # FILE NAVIGATION
        # 
        self.current_directory_label = tk.Label(self.main_frame, text="Current Directory:")
        self.current_directory_label.grid(row=11, column=0, pady=5, padx=5)
        # 
        self.current_directory_entry = tk.Entry(self.main_frame, width=50)
        self.current_directory_entry.grid(row=11, column=1, pady=5, padx=5)
        # 
        self.go_up_button = tk.Button(self.main_frame, text="Go Up", command=self.go_up_directory, width=20, height=2)
        self.go_up_button.grid(row=11, column=2, pady=5, padx=5)
        # 
        self.open_directory_button = tk.Button(self.main_frame, text="Open Directory", command=self.open_directory, width=20, height=2)
        self.open_directory_button.grid(row=11, column=3, pady=5, padx=5)
        
        # IMAGE INFO / SYS INFO
        # 
        self.status_label = tk.Label(self.main_frame, text="File System Summary", pady=10)
        self.status_label.grid(row=4, column=0, columnspan=3)
        # 
        self.size_label = tk.Label(self.main_frame, text="")
        self.size_label.grid(row=5, column=0, columnspan=3)
        # 
        self.sectors_label = tk.Label(self.main_frame, text="")
        self.sectors_label.grid(row=6, column=0, columnspan=3)
        # 
        self.block_size_label = tk.Label(self.main_frame, text="")
        self.block_size_label.grid(row=7, column=0, columnspan=3)
        # 
        self.partition_type_label = tk.Label(self.main_frame, text="")
        self.partition_type_label.grid(row=8, column=0, columnspan=3)

        # Display Partitions
        self.partition_listbox = tk.Listbox(self.main_frame, height=10, width=107)
        self.partition_listbox.grid(row=9, column=0, columnspan=3, pady=5, padx=5)

        self.regex_pattern_label = tk.Label(self.main_frame, text="Enter Regular Expression:")
        self.regex_pattern_label.grid(row=12, column=0, pady=5, padx=5)

        self.regex_pattern_entry = tk.Entry(self.main_frame)
        self.regex_pattern_entry.grid(row=12, column=1, pady=5, padx=5)

        self.search_unallocated_space_button = tk.Button(self.main_frame, text="Search Unallocated Space", command=self.search_unallocated_space_gui, width=20, height=2)
        self.search_unallocated_space_button.grid(row=12, column=2, pady=5, padx=5)

        # Output
        self.output_text = tk.Text(self.main_frame, wrap=tk.WORD, height=10, width=80)
        self.output_text.grid(row=10, column=0, columnspan=3, pady=5, padx=5)

    def open_evidence_file_gui(self):
        file_path = filedialog.askopenfilename(title="Select Evidence File",
            filetypes=[
                ("All Files", "*.*"), 
                ("Disk Image Files", "*.img;*.iso;*.dd;*.vmdk;*.E01"),
                ("Raw Disk Image", "*.img"),
                ("ISO Image", "*.iso"),
                ("DD Image", "*.dd"),
                ("VMDK Image", "*.vmdk")
            ])
        if file_path:
            if self.base_init.open_evidence_file(file_path):
                self.show_filesystem_info()

    def list_partitions_gui(self):
        if self.base_init.evidence_file:
            partitions = self.base_init.list_partitions()
            self.partition_listbox.delete(0, tk.END)
            for partition in partitions:
                self.partition_listbox.insert(tk.END, partition)

    def open_partition_gui(self):
        if self.base_init.evidence_file:
            partition_num_str = self.partition_entry.get()
            try:
                partition_num = int(partition_num_str)
            except ValueError:
                self.show_error_popup(f"Invalid partition number: {partition_num_str}")
                return

            if self.base_init.open_partition(partition_num):
                self.status_label.config(text=f"Partition {partition_num} opened.")

    def list_files_gui(self):
        if self.base_init.file_system:
            directory_path = self.directory_entry.get() or "/"
            try:
                files = self.base_init.list_files_in_directory(directory_path)
                self.output_text.delete(1.0, tk.END)  # Clear previous content
                for file in files:
                    self.output_text.insert(tk.END, f"{file}\n")
                
                # Update the current directory entry
                self.current_directory_entry.delete(0, tk.END)
                self.current_directory_entry.insert(0, directory_path)
            except Exception as e:
                self.show_error_popup(f"Error listing files: {str(e)}")

    def go_up_directory(self):
        current_path = self.current_directory_entry.get()
        parent_path = os.path.dirname(current_path)
        self.current_directory_entry.delete(0, tk.END)
        self.current_directory_entry.insert(0, parent_path)
        self.list_files_gui()

    def open_directory(self):
        new_path = self.current_directory_entry.get()
        self.base_init.list_files_in_directory(new_path)

    def display_file_details_command(self):
        if self.base_init.file_system:
            file_path = self.file_path_entry.get()
            try:
                details = self.base_init.display_file_details(file_path)
                self.output_text.delete(1.0, tk.END)  # Clear previous content
                self.output_text.insert(tk.END, details)
            except Exception as e:
                self.show_error_popup(f"Error displaying file details: {str(e)}")

    def show_filesystem_info(self):
        size_label_text, sectors_label_text, block_size_label_text, partition_type_text = self.base_init.show_filesystem_info()
        self.size_label.config(text=size_label_text)
        self.sectors_label.config(text=sectors_label_text)
        self.block_size_label.config(text=block_size_label_text)
        self.partition_type_label.config(text=partition_type_text)

    def show_error_popup(self, error_message):
        messagebox.showerror("Error", error_message)

    def search_unallocated_space_gui(self):
        if self.base_init.file_system:
            regex_pattern = self.regex_pattern_entry.get()
            try:
                matches = self.base_init.search_unallocated_space(regex_pattern)
                self.output_text.delete(1.0, tk.END)  # Clear previous content
                for match in matches:
                    self.output_text.insert(tk.END, f"{match}\n")
            except Exception as e:
                self.show_error_popup(f"Error searching unallocated space: {str(e)}")


if __name__ == "__main__":
    base_init = ForensicAnalysisTool()
    app = GUI(base_init)
    app.mainloop()
