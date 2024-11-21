import os
import json
from pathlib import Path

def find_folders_with_h_files(root_dir):
    folders_with_h = []
    # 遍历root_dir下的所有文件夹和文件
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.h'):
                # 使用Path获取相对路径
                relative_path = Path(root).relative_to(root_dir)
                folders_with_h.append(f"${{workspaceFolder}}/{str(relative_path)}")
                # 找到.h文件后，跳出循环，继续检查下一个文件夹
                break
    return folders_with_h

def write_paths_to_file(paths, file_name):
    with open(file_name, 'w') as file:
        for path in paths:
            file.write(f"{path}\n")

def append_to_cpp_properties(paths):
    cpp_properties_path = Path('.vscode/c_cpp_properties.json')
    if cpp_properties_path.exists():
        with open(cpp_properties_path, 'r') as file:
            cpp_properties = json.load(file)
        
        for config in cpp_properties.get('configurations', []):
            include_path = config.get('includePath', [])
            include_path.extend(paths)
            config['includePath'] = include_path
        
        with open(cpp_properties_path, 'w') as file:
            json.dump(cpp_properties, file, indent=4)
    else:
        print(f"{cpp_properties_path} 文件不存在，请确保C/C++插件已正确配置。")

if __name__ == "__main__":
    root_directory = '.'  # 当前目录
    output_file = 'folders_with_h_files.txt'
    folders = find_folders_with_h_files(root_directory)
    write_paths_to_file(folders, output_file)
    append_to_cpp_properties(folders)
    print(f"完成！包含.h文件的文件夹路径已保存到{output_file}，并已追加到C/C++插件的搜索路径中。")