import pickle
import shelve


class ResultDB:
    def __init__(self, db_path):
        self.db_path = db_path
        self.db_params = dict(protocol=pickle.HIGHEST_PROTOCOL, writeback=True)

    def __setitem__(self, idp_entity_id, test_result):
        with shelve.open(self.db_path, **self.db_params) as db:
            if idp_entity_id not in db:
                db[idp_entity_id] = {}

            db[idp_entity_id][test_result.test_id] = test_result

    def __getitem__(self, idp_entity_id):
        with shelve.open(self.db_path, **self.db_params) as db:
            return list(db[idp_entity_id].values())

    def __iter__(self):
        with shelve.open(self.db_path, **self.db_params) as db:
            return iter(list(db.keys()))
