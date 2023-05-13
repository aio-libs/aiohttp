Made ``StreamReader.read_nowait()`` async to avoid blocking the program in a busy loop (and ensure the client timeout works in this situation) -- by :user:`Dreamsorcerer`.
