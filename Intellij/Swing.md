# JTree主要类

- DefaultMutableTreeNode 一个父节点，多个子节点，一个用户对象的可变节点
- DefaultTreeModel 提供对子节点的访问方法，但是不提供对父节点的访问方法
- DefaultTreeCellEditor 把编辑器组件放在节点图标旁边
- DefaultTreeCellRenderer 具有字体、颜色、图标访问方法的JLabel扩展，提供图标的缺省值
- TreePath 一个节点到另外一个节点的路径，路径的节点存储在一个数组中，路径用于在选取内容之间进行通信



# 扩展 DefaultMutableTreeNode

```java
class FileNode extends DefaultMutableTreeNode{
    private boolean explored = false;
    
    public FileNode(File file){
        setUserObject(file);
    }
    
    @Override
    public boolean getAllowsChildren(){
        return isDirectory();
    }
    
    @Override
    public boolean isLeaf(){return !isDirectory();}
    
    public File getFile(){
        return (File)getUserObject();
    }
    
    public boolean isExplored(){return explored;}
    
    public boolean isDirectory(){
        File file = (File)getUserObject();
        return file.isDirectory();
    }
    
    public String toString(){
        return file.getName();
    }
    
    public void explore(){
        if(!isDirectory()) return;
        if(!isExplored()){
            File file = getFile();
            File[] children = file.listFiles();
            for(int i=0; i<children.length; i++){
                add(new FileNode(children[i]));
            }
            explored = true;
        }
    }
}
```

