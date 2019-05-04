FROM python:3.7
COPY junospyez-ossh-server-master junospyez-ossh-server-master
WORKDIR junospyez-ossh-server-master
RUN pip install -r requirements.txt
RUN ls
EXPOSE 9000 
ENTRYPOINT ["python", "run_server.py"]