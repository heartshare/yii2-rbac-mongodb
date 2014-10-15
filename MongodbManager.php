<?php
/**
 * Created by PhpStorm.
 * User: 俊杰
 * Date: 2014/10/14
 * Time: 13:08
 */

namespace yii\rbac;

use Yii;
use yii\base\InvalidCallException;
use yii\base\InvalidParamException;
use yii\db\Expression;
use yii\di\Instance;
use yii\mongodb\Connection;
use yii\mongodb\Query;


class MongodbManager extends BaseManager
{

    /**
     * @var Connection|string the DB connection object
     */

    public $db = 'mongodb';

    /**
     * @var string the name of the table storing authorization items. Defaults to "auth_item".
     */
    public $itemTable = 'auth_item';
    /**
     * @var string the name of the table storing authorization item hierarchy. Defaults to "auth_item_child".
     */
    public $itemChildTable = 'auth_item_child';
    /**
     * @var string the name of the table storing authorization item assignments. Defaults to "auth_assignment".
     */
    public $assignmentTable = 'auth_assignment';
    /**
     * @var string the name of the table storing rules. Defaults to "auth_rule".
     */
    public $ruleTable = 'auth_rule';

    public function init()
    {
        parent::init();
        $this->db = Instance::ensure($this->db, Connection::className());
        $this->db->getCollection($this->itemTable)->createIndex(['name' => 1], ['unique' => true]);
        $this->db->getCollection($this->ruleTable)->createIndex(['name' => 1], ['unique' => true]);
    }

    /**
     * Returns the named auth item.
     * @param string $name the auth item name.
     * @return Item the auth item corresponding to the specified name. Null is returned if no such item.
     */
    protected function getItem($name)
    {
        $query = new Query();
        $row = $query->from($this->itemTable)
            ->where(['name' => $name])
            ->one($this->db);
        if ($row === false) {
            return null;
        }

        if (!isset($row['data']) || ($data = @unserialize($row['data'])) === false) {
            $row['data'] = null;
        }

        return $this->populateItem($row);
    }

    protected function populateItem($row)
    {
        $class = $row['type'] == Item::TYPE_PERMISSION ? Permission::className() : Role::className();

        if (!isset($row['data']) || ($data = @unserialize($row['data'])) === false) {
            $data = null;
        }

        return new $class([
            'name' => $row['name'],
            'type' => $row['type'],
            'description' => $row['description'],
            'ruleName' => $row['rule_name'],
            'data' => $data,
            'createdAt' => $row['created_at'],
            'updatedAt' => $row['updated_at'],
        ]);
    }

    /**
     * Returns the items of the specified type.
     * @param integer $type the auth item type (either [[Item::TYPE_ROLE]] or [[Item::TYPE_PERMISSION]]
     * @return Item[] the auth items of the specified type.
     */
    protected function getItems($type)
    {
        $query = (new Query)
            ->from($this->itemTable)
            ->where(['type' => $type]);

        $items = [];
        foreach ($query->all($this->db) as $row) {
            $items[$row['name']] = $this->populateItem($row);
        }

        return $items;
    }

    /**
     * Adds an auth item to the RBAC system.
     * @param Item $item
     * @return boolean whether the auth item is successfully added to the system
     * @throws \Exception if data validation or saving fails (such as the name of the role or permission is not unique)
     */
    protected function addItem($item)
    {
        $time = time();
        if ($item->createdAt === null) {
            $item->createdAt = $time;
        }
        if ($item->updatedAt === null) {
            $item->updatedAt = $time;
        }

        $this->db->getCollection($this->itemTable)
            ->insert([
                'name' => $item->name,
                'type' => $item->type,
                'description' => $item->description,
                'rule_name' => $item->ruleName,
                'data' => $item->data === null ? null : serialize($item->data),
                'created_at' => $item->createdAt,
                'updated_at' => $item->updatedAt,
            ]);

        return true;
    }

    /**
     * Adds a rule to the RBAC system.
     * @param Rule $rule
     * @return boolean whether the rule is successfully added to the system
     * @throws \Exception if data validation or saving fails (such as the name of the rule is not unique)
     */
    protected function addRule($rule)
    {
        $time = time();
        if ($rule->createdAt === null) {
            $rule->createdAt = $time;
        }
        if ($rule->updatedAt === null) {
            $rule->updatedAt = $time;
        }
        $this->db->getCollection($this->ruleTable)
            ->insert([
                'name' => $rule->name,
                'data' => serialize($rule),
                'created_at' => $rule->createdAt,
                'updated_at' => $rule->updatedAt,
            ]);

        return true;
    }

    /**
     * Removes an auth item from the RBAC system.
     * @param Item $item
     * @return boolean whether the role or permission is successfully removed
     * @throws \Exception if data validation or saving fails (such as the name of the role or permission is not unique)
     */
    protected function removeItem($item)
    {
        $this->db->getCollection($this->itemChildTable)->remove(['or', 'parent=:name', 'child=:name'], [':name' => $item->name]);
        $this->db->getCollection($this->assignmentTable)->remove(['item_name' => $item->name]);
        $this->db->getCollection($this->itemTable)->remove(['name' => $item->name]);
        return true;
    }

    /**
     * Removes a rule from the RBAC system.
     * @param Rule $rule
     * @return boolean whether the rule is successfully removed
     * @throws \Exception if data validation or saving fails (such as the name of the rule is not unique)
     */
    protected function removeRule($rule)
    {
        $this->db->getCollection($this->itemTable)->remove(['rule_name' => $rule->name]);
        $this->db->getCollection($this->ruleTable)->remove(['name' => $rule->name]);
        return true;
    }

    /**
     * Updates an auth item in the RBAC system.
     * @param string $name the old name of the auth item
     * @param Item $item
     * @return boolean whether the auth item is successfully updated
     * @throws \Exception if data validation or saving fails (such as the name of the role or permission is not unique)
     */
    protected function updateItem($name, $item)
    {
        if ($item->name != $name) {
            $this->db->getCollection($this->itemChildTable)->update(['parent' => $item->name], ['parent' => $name]);
            $this->db->getCollection($this->itemChildTable)->update(['child' => $item->name], ['child' => $name]);
            $this->db->getCollection($this->assignmentTable)->update(['item_name' => $item->name], ['item_name' => $name]);
        }

        $item->updatedAt = time();

        $this->db->getCollection($this->itemTable)->update([
            'name' => $item->name,
            'description' => $item->description,
            'rule_name' => $item->ruleName,
            'data' => $item->data === null ? null : serialize($item->data),
            'updated_at' => $item->updatedAt,
        ], [
            'name' => $name,
        ]);
        return true;
    }

    /**
     * Updates a rule to the RBAC system.
     * @param string $name the old name of the rule
     * @param Rule $rule
     * @return boolean whether the rule is successfully updated
     * @throws \Exception if data validation or saving fails (such as the name of the rule is not unique)
     */
    protected function updateRule($name, $rule)
    {
        if ($rule->name !== $name) {
            $this->db->getCollection($this->itemTable)->update(['rule_name' => $rule->name], ['rule_name' => $name]);
        }

        $rule->updatedAt = time();

        $this->db->getCollection($this->ruleTable)->update([
            'name' => $rule->name,
            'data' => serialize($rule),
            'updated_at' => $rule->updatedAt,
        ], [
            'name' => $name,
        ]);

        return true;
    }

    /**
     * Checks if the user has the specified permission.
     * @param string|integer $userId the user ID. This should be either an integer or a string representing
     * the unique identifier of a user. See [[\yii\web\User::id]].
     * @param string $permissionName the name of the permission to be checked against
     * @param array $params name-value pairs that will be passed to the rules associated
     * with the roles and permissions assigned to the user.
     * @return boolean whether the user has the specified permission.
     * @throws \yii\base\InvalidParamException if $permissionName does not refer to an existing permission
     */
    public function checkAccess($userId, $permissionName, $params = [])
    {
        $assignments = $this->getAssignments($userId);
        return $this->checkAccessRecursive($userId, $permissionName, $params, $assignments);
    }

    /**
     * Performs access check for the specified user.
     * This method is internally called by [[checkAccess()]].
     * @param string|integer $user the user ID. This should can be either an integer or a string representing
     * the unique identifier of a user. See [[\yii\web\User::id]].
     * @param string $itemName the name of the operation that need access check
     * @param array $params name-value pairs that would be passed to rules associated
     * with the tasks and roles assigned to the user. A param with name 'user' is added to this array,
     * which holds the value of `$userId`.
     * @param Assignment[] $assignments the assignments to the specified user
     * @return boolean whether the operations can be performed by the user.
     */

    protected function checkAccessRecursive($user, $itemName, $params, $assignments)
    {
        if (($item = $this->getItem($itemName)) === null) {
            return false;
        }

        Yii::trace($item instanceof Role ? "Checking role: $itemName" : "Checking permission: $itemName", __METHOD__);

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (isset($assignments[$itemName]) || in_array($itemName, $this->defaultRoles)) {
            return true;
        }

        $parents = [];
        $query = new Query;
        $temp = $query->select(['parent'])
            ->from($this->itemChildTable)
            ->where(['child' => $itemName]);
        foreach ($temp->all($this->db) as $item) {
            $parents[] = $item['parent'];
        }
        foreach ($parents as $parent) {
            if ($this->checkAccessRecursive($user, $parent, $params, $assignments)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the roles that are assigned to the user via [[assign()]].
     * Note that child roles that are not assigned directly to the user will not be returned.
     * @param string|integer $userId the user ID (see [[\yii\web\User::id]])
     * @return Role[] all roles directly or indirectly assigned to the user. The array is indexed by the role names.
     */
    public function getRolesByUser($userId)
    {
        if (empty($userId)) {
            return [];
        }

        $itemName = [];
        $temp = (new Query())->select('item_name')
            ->from($this->assignmentTable)
            ->where(['user_id' => (string)$userId]);
        foreach ($temp->all($this->db) as $row) {
            $itemName[] = $row['item_name'];
        }
        $query = (new Query)->from($this->itemTable)
            ->where(['name' => $itemName]);

        $roles = [];
        foreach ($query->all($this->db) as $row) {
            $roles[$row['name']] = $this->populateItem($row);
        }
        return $roles;
    }

    /**
     * Returns all permissions that the specified role represents.
     * @param string $roleName the role name
     * @return Permission[] all permissions that the role represents. The array is indexed by the permission names.
     */
    public function getPermissionsByRole($roleName)
    {
        $childrenList = $this->getChildrenList();
        $result = [];
        $this->getChildrenRecursive($roleName, $childrenList, $result);
        if (empty($result)) {
            return [];
        }
        $query = (new Query)->from($this->itemTable)->where([
            'type' => Item::TYPE_PERMISSION,
            'name' => array_keys($result),
        ]);
        $permissions = [];
        foreach ($query->all($this->db) as $row) {
            $permissions[$row['name']] = $this->populateItem($row);
        }
        return $permissions;
    }

    /**
     * Returns all permissions that the user has.
     * @param string|integer $userId the user ID (see [[\yii\web\User::id]])
     * @return Permission[] all permissions that the user has. The array is indexed by the permission names.
     */
    public function getPermissionsByUser($userId)
    {
        if (empty($userId)) {
            return [];
        }

        $query = (new Query)->select(['item_name'])
            ->from($this->assignmentTable)
            ->where(['user_id' => (string)$userId]);
        $temp = [];
        foreach ($query->all($this->db) as $row) {
            $temp[] = $row['item_name'];
        }

        $childrenList = $this->getChildrenList();
        $result = [];
        foreach ($temp as $roleName) {
            $this->getChildrenRecursive($roleName, $childrenList, $result);
        }

        if (empty($result)) {
            return [];
        }

        $query = (new Query)->from($this->itemTable)->where([
            'type' => Item::TYPE_PERMISSION,
            'name' => array_keys($result),
        ]);
        $permissions = [];
        foreach ($query->all($this->db) as $row) {
            $permissions[$row['name']] = $this->populateItem($row);
        }
        return $permissions;
    }

    /**
     * Returns the children for every parent.
     * @return array the children list. Each array key is a parent item name,
     * and the corresponding array value is a list of child item names.
     */
    protected function getChildrenList()
    {
        $query = (new Query)->from($this->itemChildTable);
        $parents = [];
        foreach ($query->all($this->db) as $row) {
            $parents[$row['parent']][] = $row['child'];
        }
        return $parents;
    }

    /**
     * Recursively finds all children and grand children of the specified item.
     * @param string $name the name of the item whose children are to be looked for.
     * @param array $childrenList the child list built via [[getChildrenList()]]
     * @param array $result the children and grand children (in array keys)
     */
    protected function getChildrenRecursive($name, $childrenList, &$result)
    {
        if (isset($childrenList[$name])) {
            foreach ($childrenList[$name] as $child) {
                $result[$child] = true;
                $this->getChildrenRecursive($child, $childrenList, $result);
            }
        }
    }

    /**
     * Returns the rule of the specified name.
     * @param string $name the rule name
     * @return Rule the rule object, or null if the specified name does not correspond to a rule.
     */
    public function getRule($name)
    {
        $row = (new Query)->select(['data'])
            ->from($this->ruleTable)
            ->where(['name' => $name])
            ->one($this->db);
        return $row === false ? null : unserialize($row['data']);
    }

    /**
     * Returns all rules available in the system.
     * @return Rule[] the rules indexed by the rule names
     */
    public function getRules()
    {
        $query = (new Query)->from($this->ruleTable);

        $rules = [];
        foreach ($query->all($this->db) as $row) {
            $rules[$row['name']] = unserialize($row['data']);
        }

        return $rules;
    }

    /**
     * Adds an item as a child of another item.
     * @param Item $parent
     * @param Item $child
     * @throws \yii\base\Exception if the parent-child relationship already exists or if a loop has been detected.
     */
    public function addChild($parent, $child)
    {
        if ($parent->name === $child->name) {
            throw new InvalidParamException("Cannot add '{$parent->name}' as a child of itself.");
        }

        if ($parent instanceof Permission && $child instanceof Role) {
            throw new InvalidParamException("Cannot add a role as a child of a permission.");
        }

        if ($this->detectLoop($parent, $child)) {
            throw new InvalidCallException("Cannot add '{$child->name}' as a child of '{$parent->name}'. A loop has been detected.");
        }

        $this->db->getCollection($this->itemChildTable)->insert(['parent' => $parent->name, 'child' => $child->name]);

        return true;
    }

    protected function detectLoop($parent, $child)
    {
        if ($child->name === $parent->name) {
            return true;
        }
        foreach ($this->getChildren($child->name) as $grandchild) {
            if ($this->detectLoop($parent, $grandchild)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Removes a child from its parent.
     * Note, the child item is not deleted. Only the parent-child relationship is removed.
     * @param Item $parent
     * @param Item $child
     * @return boolean whether the removal is successful
     */
    public function removeChild($parent, $child)
    {
        return $this->db->getCollection($this->itemChildTable)
            ->remove(['parent' => $parent->name, 'child' => $child->name]) === true;
    }

    /**
     * Removed all children form their parent.
     * Note, the children items are not deleted. Only the parent-child relationships are removed.
     * @param Item $parent
     * @return boolean whether the removal is successful
     */
    public function removeChildren($parent)
    {
        return $this->db->getCollection($this->itemChildTable)
            ->remove(['parent' => $parent->name]) === true;
    }

    /**
     * Returns a value indicating whether the child already exists for the parent.
     * @param Item $parent
     * @param Item $child
     * @return boolean whether `$child` is already a child of `$parent`
     */
    public function hasChild($parent, $child)
    {
        return (new Query)
            ->from($this->itemChildTable)
            ->where(['parent' => $parent->name, 'child' => $child->name])
            ->one($this->db) !== false;
    }

    /**
     * Returns the child permissions and/or roles.
     * @param string $name the parent name
     * @return Item[] the child permissions and/or roles
     */
    public function getChildren($name)
    {
        $query = (new Query)
            ->select(['name', 'type', 'description', 'rule_name', 'data', 'created_at', 'updated_at'])
            ->from([$this->itemTable, $this->itemChildTable])
            ->where(['parent' => $name, 'name' => new Expression('child')]);
        $children = [];
        foreach ($query->all($this->db) as $row) {
            $children[$row['name']] = $this->populateItem($row);
        }

        return $children;
    }

    /**
     * Assigns a role to a user.
     *
     * @param Role $role
     * @param string|integer $userId the user ID (see [[\yii\web\User::id]])
     * @return Assignment the role assignment information.
     * @throws \Exception if the role has already been assigned to the user
     */
    public function assign($role, $userId)
    {
        $assignment = new Assignment([
            'userId' => (string)$userId,
            'roleName' => $role->name,
            'createdAt' => time(),
        ]);
        if (!(new Query())->from($this->assignmentTable)->where(['user_id' => $assignment->userId, 'item_name' => $assignment->roleName])->one($this->db)) {
            $this->db->getCollection($this->assignmentTable)
                ->insert([
                    'user_id' => $assignment->userId,
                    'item_name' => $assignment->roleName,
                    'created_at' => $assignment->createdAt,
                ]);
        }

        return $assignment;
    }

    /**
     * Revokes a role from a user.
     * @param Role $role
     * @param string|integer $userId the user ID (see [[\yii\web\User::id]])
     * @return boolean whether the revoking is successful
     */
    public function revoke($role, $userId)
    {
        if (empty($userId)) {
            return false;
        }

        return $this->db->getCollection($this->assignmentTable)
            ->remove(['user_id' => (string)$userId, 'item_name' => $role->name]) === true;

    }

    /**
     * Revokes all roles from a user.
     * @param mixed $userId the user ID (see [[\yii\web\User::id]])
     * @return boolean whether the revoking is successful
     */
    public function revokeAll($userId)
    {
        if (empty($userId)) {
            return false;
        }

        return $this->db->getCollection($this->assignmentTable)
            ->remove(['user_id' => (string)$userId]) === true;
    }

    /**
     * Returns the assignment information regarding a role and a user.
     * @param string|integer $userId the user ID (see [[\yii\web\User::id]])
     * @param string $roleName the role name
     * @return Assignment the assignment information. Null is returned if
     * the role is not assigned to the user.
     */
    public function getAssignment($roleName, $userId)
    {
        if (empty($userId)) {
            return null;
        }

        $row = (new Query)->from($this->assignmentTable)
            ->where(['user_id' => (string)$userId, 'item_name' => $roleName])
            ->one($this->db);

        if ($row === false) {
            return null;
        }

        return new Assignment([
            'userId' => $row['user_id'],
            'roleName' => $row['item_name'],
            'createdAt' => $row['created_at'],
        ]);
    }

    /**
     * Returns all role assignment information for the specified user.
     * @param string|integer $userId the user ID (see [[\yii\web\User::id]])
     * @return Assignment[] the assignments indexed by role names. An empty array will be
     * returned if there is no role assigned to the user.
     */
    public function getAssignments($userId)
    {
        if (empty($userId)) {
            return [];
        }

        $query = (new Query)
            ->from($this->assignmentTable)
            ->where(['user_id' => (string)$userId]);
        $assignments = [];
        foreach ($query->all($this->db) as $row) {
            $assignments[$row['item_name']] = new Assignment([
                'userId' => $row['user_id'],
                'roleName' => $row['item_name'],
                'createdAt' => $row['created_at'],
            ]);
        }

        return $assignments;
    }

    /**
     * Removes all authorization data, including roles, permissions, rules, and assignments.
     */
    public function removeAll()
    {
        $this->removeAllAssignments();
        $this->db->getCollection($this->itemChildTable)->drop();
        $this->db->getCollection($this->itemTable)->drop();
        $this->db->getCollection($this->ruleTable)->drop();
    }

    /**
     * Removes all permissions.
     * All parent child relations will be adjusted accordingly.
     */
    public function removeAllPermissions()
    {
        $this->removeAllItems(Item::TYPE_PERMISSION);
    }

    /**
     * Removes all roles.
     * All parent child relations will be adjusted accordingly.
     */
    public function removeAllRoles()
    {
        $this->removeAllItems(Item::TYPE_ROLE);
    }

    protected function removeAllItems($type)
    {
        $names = [];
        $query = (new Query)
            ->select(['name'])
            ->from($this->itemTable)
            ->where(['type' => $type]);
        foreach ($query->all($this->db) as $line) {
            $names[] = $line['name'];
        }

        if (empty($names)) {
            return;
        }
        $key = $type == Item::TYPE_PERMISSION ? 'child' : 'parent';
        $this->db->getCollection($this->itemChildTable)->remove([$key => $names]);
        $this->db->getCollection($this->assignmentTable)->remove(['item_name' => $names]);
        $this->db->getCollection($this->itemTable)->remove(['type' => $type]);
    }

    /**
     * Removes all rules.
     * All roles and permissions which have rules will be adjusted accordingly.
     */
    public function removeAllRules()
    {
        $this->db->getCollection($this->itemTable)->update([], ['ruleName' => null]);
        $this->db->getCollection($this->ruleTable)->drop();
    }

    /**
     * Removes all role assignments.
     */
    public function removeAllAssignments()
    {
        $this->db->getCollection($this->assignmentTable)->drop();
    }
}