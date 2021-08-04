import unittest
import sys
sys.path.append('./src')
from main import main

class TestMain(unittest.TestCase):
    def test_main(self):
        """ Test Main class """
        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 0)

if __name__ == '__main__':
    unittest.main()
