FROM python:3.7
RUN git clone https://github.com/natemellendorf/configpy-node.git
WORKDIR configpy-node/junospyez-ossh-server-master
RUN pip install -r requirements.txt
EXPOSE 9000 
ENTRYPOINT ["python", "run_server.py"]