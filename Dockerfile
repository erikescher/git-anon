FROM ubuntu:20.04

RUN apt update
RUN apt install --yes git gpg python3 python3-pip vim
COPY dist/git_anon-0.1.1-py3-none-any.whl .
RUN pip3 install ./git_anon-0.1.1-py3-none-any.whl


WORKDIR /home/user
RUN useradd user
RUN chown user:user /home/user
COPY system_test.py .
# USER user

ENV GIT_ANON_LOGLEVEL=10
ENV GIT_ANON_RETHROW_EXCEPTIONS="True"
ENV GIT_ANON_SYSTEM_TEST_AUTHORIZED="True"
ENV GIT_TRACE=1