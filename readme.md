# 创建虚拟环境
python -m venv venv

# 安装包

pip install -r requirments -i https://tuna.tsinghua.edu.cn/simple

# 然后使虚拟环境生效（windows）
venv\Scripts\activate

source venv/bin/activate  # （Linux激活虚拟环境）

# #运行

python app.py