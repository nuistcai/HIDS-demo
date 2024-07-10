from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# 示例数据
ids_data = [
    {'id': 1, 'type': 'DoS', 'status': 'Detected', 'timestamp': '2024-05-27 12:00:00'},
    {'id': 2, 'type': 'PortScan', 'status': 'Detected', 'timestamp': '2024-05-27 12:05:00'},
    {'id': 3, 'type': 'BruteForce', 'status': 'Mitigated', 'timestamp': '2024-05-27 12:10:00'}
]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/ids_data')
def get_ids_data():
    return jsonify(ids_data)

@app.route('/api/add_alert', methods=['POST'])
def add_alert():
    new_alert = request.json
    ids_data.append(new_alert)
    return jsonify({'message': 'Alert added successfully!'}), 201

if __name__ == '__main__':
    app.run(debug=True)
