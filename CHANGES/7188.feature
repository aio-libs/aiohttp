Added a graceful shutdown period which allows pending tasks to complete before the application's cleanup is called. The period can be adjusted with the ``shutdown_timeout`` parameter -- by :user:`Dreamsorcerer`.
