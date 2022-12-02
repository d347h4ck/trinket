from schemas import User, Group


def check_group_affiliation(group: Group, query_group_id: int):
    res = False
    if group.id == query_group_id:
        return True

    for child in group.children:
        res = res or check_group_affiliation(child, query_group_id)
        if res:
            break

    return res


def get_all_user_groups(group: Group):
    res = list()
    res.append(group.id)
    for child in group.children:
        res += get_all_user_groups(child)

    return res


def get_safe_from_user(user, safe_id):
    for safe in user['safes']:
        if safe['id'] == safe_id:
            # print(safe)
            return safe
    else:
        return None
