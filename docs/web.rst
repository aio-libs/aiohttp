.. _aiohttp-web:

Server
======

.. module:: aiohttp.web

The page contains all information about aiohttp Server API:


.. toctree::
   :name: server
   :maxdepth: 3

   Tutorial <https://demos.aiohttp.org>
   Quickstart <web_quickstart>
   Advanced Usage <web_advanced>
   Low Level <web_lowlevel>
   Reference <web_reference>
   Web Exceptions <web_exceptions>
   Logging <logging>
   Testing <testing>
   Deployment <deployment>


SSE指南
-------

快速上手
~~~~~~~~

- 使用 ``EventSourceResponse`` 或 ``sse_response`` 上下文即可开启 SSE 流。
- 基本用法：

  .. code-block:: python

     from aiohttp import web
     from aiohttp.sse import sse_response

     async def handler(request: web.Request) -> web.StreamResponse:
         async with sse_response(request, heartbeat=15, json=True) as resp:
             await resp.send({"hello": "world"}, event="message", id=1)
             await resp.comment("keep-alive")
             return resp

事件格式
~~~~~~~~

- 每个事件由若干行组成，常见字段： ``event:``, ``id:``, ``retry:``, ``data:``；行尾使用 ``\n``，事件之间以空行分隔。
- ``data`` 支持多行，按 SSE 标准每一行都以 ``data: `` 前缀输出。

心跳与重连
~~~~~~~~~~

- 默认心跳间隔可通过 ``heartbeat`` 参数设置（秒），会周期发送注释行 ``:keep-alive``，保持代理与连接活跃。
- 客户端可依赖 ``retry: <ms>`` 控制重连退避时间；服务端仅负责输出该字段。

背压策略
~~~~~~~~

- 当生产速度快于网络发送速度时，可启用内部队列并设置策略：
  - ``block``：生产端阻塞等待队列可用（默认）。
  - ``drop_old``：队列满时丢弃最旧事件，再入队新事件。
  - ``drop_new``：队列满时直接丢弃新事件。

压缩
~~~~

- 可选支持 ``compress="br"`` 或 ``compress="zstd"``，依赖条件导入 ``brotli`` 或 ``zstandard`` 库；若不可用将自动回退为不压缩。
- 某些代理/浏览器对 SSE 压缩支持不一致，建议在链路与客户端确认后再开启。

常见坑
~~~~~~

- 代理与缓存：务必设置 ``Cache-Control: no-cache``，并考虑 ``X-Accel-Buffering: no``（如使用 Nginx）。
- 超时：长连接需要适当的心跳与反向代理 ``timeout`` 配置，避免被过早关闭。
- 多重编码：不要同时启用服务器端与中间层的压缩，避免重复编码导致客户端无法解析。
