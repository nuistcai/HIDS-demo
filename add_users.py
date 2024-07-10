from app import app, db, User, bcrypt

with app.app_context():
    # 创建数据库和表
    db.create_all()

    # 检查是否已存在用户，避免重复添加
    if User.query.count() == 0:
        hashed_password = bcrypt.generate_password_hash('123').decode('utf-8')
        admin_user = User(username='user1', password=hashed_password)
        db.session.add(admin_user)
        db.session.commit()

    print('User added successfully!')
