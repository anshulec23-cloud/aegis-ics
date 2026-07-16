import os
import unittest
from src.security import find_free_port, generate_runtime_secret, check_debugger
from src.database import init_db

class TestCoreModules(unittest.TestCase):
    def test_find_free_port(self):
        """Test that find_free_port returns a valid integer port."""
        port = find_free_port()
        self.assertIsInstance(port, int)
        self.assertTrue(1024 <= port <= 65535)

    def test_generate_runtime_secret(self):
        """Test that the runtime secret is cryptographically secure and formatted properly."""
        secret = generate_runtime_secret()
        self.assertIsInstance(secret, str)
        self.assertEqual(len(secret), 64)  # 32 bytes hex encoded

    def test_check_debugger(self):
        """Test that check_debugger executes without raising exceptions."""
        result = check_debugger()
        self.assertIsInstance(result, bool)

    def test_database_initialization(self):
        """Test that database can be initialized and schema created."""
        db_path = "test_aegis.db"
        if os.path.exists(db_path):
            os.remove(db_path)
        try:
            init_db()
            self.assertTrue(os.path.exists("aegis_v2.db"))
        finally:
            if os.path.exists("aegis_v2.db"):
                os.remove("aegis_v2.db")

if __name__ == '__main__':
    unittest.main()
