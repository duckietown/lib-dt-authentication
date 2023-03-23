FROM python:3.7

WORKDIR /code
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV DISABLE_CONTRACTS=1

RUN python setup.py develop --no-deps

# run it once to see everything OK
CMD ["make test"]
