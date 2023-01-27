"""Code base runs inside a container and executes based on passed in parameters."""
import sys

import vt


class VirusTotalService:

    def run(self, argv):

        client = vt.Client(argv[0])

        url_id = vt.url_id(argv[1])
        url = client.get_object('/urls/{}', url_id)

        return_dict = {}
        for item in dir(url):
            if not item.startswith('_'):
                return_dict[item] = getattr(url, item)
        return return_dict


if __name__ == "__main__":
    print(VirusTotalService().run(sys.argv))
