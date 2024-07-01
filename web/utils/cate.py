    
""" from flask import Blueprint
from web.models import Cate
cate = Cate.query.order_by(Cate.id).all()
 """
""" data = [

    { 'id': 1, 'parent': 2, 'name': "Node1" },
    { 'id': 2, 'parent': 5, 'name': "Node2" },
    { 'id': 3, 'parent': 0, 'name': "Node3" },
    { 'id': 5, 'parent': 0, 'name': "Node5" },
    { 'id': 9, 'parent': 1, 'name': "Node9" }
] """



def find_dept_by_name(d):
    if d == 'k':
        d = 'kitchen'
    elif d == 'c':
        d = 'cocktails'
    elif d == 'b':
        d = 'bar'
    else:
        d = 'invalid department'
    return d
    

def categ(cate):
    cat = { 
        #0: { 'id': 0, 'parent': 0, 'name': "Root node", 'sub': [] }
    }

    cat = {}
    for c in cate:
        cat.setdefault(c['parent'], { 'sub': [] })
        cat.setdefault(c['id'], { 'sub': [] })
        cat[c['id']].update(c)
        cat[c['parent']]['sub'].append(cat[c['id']])

    return cat

    #return f"{jsonify(cat)}"

#function-calling
""" f = categ(data)
pprint.pprint(f) """

#return f'{f}'


""" $refs = array();
$list = array();

$sql = "SELECT item_id, parent_id, name FROM items ORDER BY name";

/** @var $pdo \PDO */
$result = $pdo->query($sql);

foreach ($result as $row)
{
    $ref = & $refs[$row['item_id']];

    $ref['parent_id'] = $row['parent_id'];
    $ref['name']      = $row['name'];

    if ($row['parent_id'] == 0)
    {
        $list[$row['item_id']] = & $ref;
    }
    else
    {
        $refs[$row['parent_id']]['children'][$row['item_id']] = & $ref;
    }
} """

""" refs = []
list = []
cate_ = None
for c in cate_:
    ref = refs[ c['id'] ]
    ref['parent'] = c['parent']
    ref['name'] = c['name']

    if c['parent'] == None:
        list[ c['id'] ] = ref
    else:
        refs[c['parent']]['child'][c['id']] = ref """




