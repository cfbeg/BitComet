const crypto = require('crypto');

class BitCometApi {
    params = {
        base_url: '',
        headers: {
            'Client-Type': 'BitComet WebUI'
        },
        client_id: '',
        device_token: ''
    }

    endpoints = {
        USER_LOGIN: "/api/webui/login",
        GET_DEVICE_TOKEN: "/api/device_token/get",
        GET_TASK_LIST: "/api_v2/task_list/get",
        POST_TASKS_ACTION: "/api_v2/tasks/action",
        POST_TASKS_DELETE: "/api_v2/tasks/delete",
        GET_TASKS_INFO: "/api/tasks/info/get",
        GET_NEW_TASK_CONFIG: "/api/config/new_task/get",
        ADD_HTTP_TASK: "/api/task/http/add",
        ADD_BT_TASK: "/api/task/bt/add",
        GET_TASK_SUMMARY: "/api/task/summary/get",
        GET_TASK_FILES: "/api/task/files/get",
        GET_TASK_TRACKERS: "/api/task/trackers/get",
        GET_TASK_SERVERS: "/api/task/servers/get",
        GET_TASK_CONNECTIONS: "/api/task/connections/get",
        GET_TASK_LOGS: "/api/task/logs/get",
        GET_TASK_PIECE_MAP: "/api/task/piece_map/get",
        GET_FLOW_GRAPH: "/api/flow_graph/get",
        GET_GLOBAL_LOGS: "/api/global_logs/get",
        GET_STATISTICS_LIST: "/api/statistics_list/get",
        GET_TASK_PEERS: "/api/task/peers/get",
        BT_TASK_BAN_IP: "/api/task/peers/ban_ip",
        BT_TASK_UNBAN_PEERS: "/api/task/peers/unban_peers",
        GET_CONNECTION_CONFIG: "/api/config/connection/get",
        SET_CONNECTION_CONFIG: "/api/config/connection/set",
        GET_DIRECTORIES_CONFIG: "/api/config/directories/get",
        SET_DIRECTORIES_CONFIG: "/api/config/directories/set",
        DOWNLOAD_DIRECTORY_ADD: "/api/config/directories/add",
        DOWNLOAD_DIRECTORY_REMOVE: "/api/config/directories/remove",
        GET_TASKS_CONFIG: "/api/config/tasks/get",
        SET_TASKS_CONFIG: "/api/config/tasks/set",
        GET_BITTORRENT_TASK_CONFIG: "/api/config/bt_task/get",
        SET_BITTORRENT_TASK_CONFIG: "/api/config/bt_task/set",
        GET_IP_FILTER_CONFIG: "/api/config/ipfilter/get",
        SET_IP_FILTER_CONFIG: "/api/config/ipfilter/set",
        IP_FILTER_UPLOAD: "/api/config/ipfilter/upload",
        IP_FILTER_DOWNLOAD: "/api/config/ipfilter/download",
        IP_FILTER_CLEAR: "/api/config/ipfilter/clear",
        IP_FILTER_UPDATE: "/api/config/ipfilter/update",
        IP_FILTER_IMPORTING_QUERY: "/api/config/ipfilter/query",
        GET_CLIENT_FILTER_CONFIG: "/api/config/client_filter/get",
        SET_CLIENT_FILTER_CONFIG: "/api/config/client_filter/set",
        CLIENT_FILTER_UPLOAD: "/api/config/client_filter/upload",
        CLIENT_FILTER_DOWNLOAD: "/api/config/client_filter/download",
        CLIENT_FILTER_CLEAR: "/api/config/client_filter/clear",
        CLIENT_FILTER_UPDATE: "/api/config/client_filter/update",
        CLIENT_FILTER_IMPORTING_QUERY: "/api/config/client_filter/query",
        GET_REMOTE_ACCESS_CONFIG: "/api/config/remote_access/get",
        SET_REMOTE_ACCESS_CONFIG: "/api/config/remote_access/set",
        GET_ABOUT_CONFIG: "/api/config/about/get",
        GET_MOBILE_APP_CONFIG: "/api/config/mobile_app/get",
        SET_MOBILE_APP_CONFIG: "/api/config/mobile_app/set",
        GET_BOUND_DEVICE_LIST: "/api/config/bound_devices/get",
        BOUND_DEVICE_RENAME: "/api/config/bound_device/rename",
        BOUND_DEVICE_REMOVE: "/api/config/bound_device/remove",
        COMETID_SIGN_IN: "/api/cometid/sign_in",
        COMETID_SIGN_OUT: "/api/cometid/sign_out",
        COMETID_QUERY: "/api/cometid/query",
        GET_FOOTER_STATUS: "/api/footer_status/get",
        POST_WEBUI_ACTION: "/api/webui/action",
        GET_NOTIFICATION_LIST: "/api/notifications/get",
        NOTIFICATION_ACTION: "/api/notifications/action"
    }

    constructor() {
        this.params.client_id = crypto.randomUUID();
        console.log('Generated client_id:', this.params.client_id);
    }

    async login(server_url, username, password) {
        this.params.base_url = server_url;
        const authentication = authEncrypt(JSON.stringify({
            'username': username,
            'password': password
        }), this.params.client_id)

        const response = await fetch(this.params.base_url + this.endpoints.USER_LOGIN, {
            method: 'POST',
            headers: this.params.headers,
            body: JSON.stringify({
                'client_id': this.params.client_id,
                authentication
            })
        });

        if (response.status !== 200) {
            console.error('Login failed with status:', response.status);
            return;
        }
        const data = await response.json();
        if (data.error_code !== 'OK') {
            console.error('Login error:', data);
            return;
        }
        return data;
    }

    async getDeviceToken(invite_token) {
        const response = await fetch(this.params.base_url + this.endpoints.GET_DEVICE_TOKEN, {
            method: 'POST',
            headers: {
                ...this.params.headers,
                'Authorization': `Bearer ${invite_token}`
            },
            body: JSON.stringify({
                invite_token,
                'device_id': this.params.client_id,
                'device_name': 'BitComet-API @ js',
                'platform': 'webui'
            })
        });

        if (response.status !== 200) {
            console.error('Get device token failed with status:', response.status);
            return;
        }
        const data = await response.json();
        if (data.error_code !== 'OK') {
            console.error('Get device token error:', data);
            return;
        }
        this.params.device_token = data.device_token;
        this.params.headers['Authorization'] = `Bearer ${this.params.device_token}`;
        return data;
    }

    async removeDevice(device_id) {
        const response = await fetch(this.params.base_url + this.endpoints.BOUND_DEVICE_REMOVE, {
            method: 'POST',
            headers: {
                ...this.params.headers,
            },
            body: JSON.stringify({
                'device_id': device_id,
            })
        });

        if (response.status !== 200) {
            console.error('Remove device failed with status:', response.status);
            return;
        }
        const data = await response.json();
        if (data.error_code !== 'OK') {
            console.error('Remove device error:', data);
            return;
        }

        for (let i = 0; i < data.bound_device_list.length; i++) {
            if (data.bound_device_list[i].id === device_id) {
                console.error('Device removal failed, device still exists:', data.bound_device_list[i]);
                return;
            }
        }
        return data;
    }

    async removeThisDevice() {
        const replaced_id = this.params.client_id.replace(/-/g, '');
        const data = await this.removeDevice(replaced_id);
        return data;
    }

    async getTaskList(json) {
        const response = await fetch(this.params.base_url + this.endpoints.GET_TASK_LIST, {
            method: 'POST',
            headers: {
                ...this.params.headers,
            },
            body: JSON.stringify(json)
        });

        if (response.status !== 200) {
            console.error('Get task list failed with status:', response.status);
            return;
        }
        const data = await response.json();
        if (data.error_code !== 'OK') {
            console.error('Get task list error:', data);
            return;
        }
        return data;
    }
}

function authEncrypt(data, uuid) {
    // ランダムソルトを生成（8バイト）
    const salt1 = crypto.randomBytes(8);
    const salt2 = crypto.randomBytes(8);

    // PBKDF2でキーを生成
    const key = crypto.pbkdf2Sync(uuid, salt1, 10000, 32, 'sha1');
    const hmacKey = crypto.pbkdf2Sync(uuid, salt2, 10000, 32, 'sha1');

    // ランダムIVを生成（16バイト）
    const iv = crypto.randomBytes(16);

    // AES-256-CBCで暗号化
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(true);

    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // データを結合
    let result = Buffer.from([3, 1]).toString('hex'); // バージョン情報
    result += salt1.toString('hex');  // salt1
    result += salt2.toString('hex');  // salt2
    result += iv.toString('hex');     // IV
    result += encrypted;              // 暗号化データ

    // HMACを計算
    const hmac = crypto.createHmac('sha256', hmacKey);
    hmac.update(Buffer.from(result, 'hex'));
    const hmacDigest = hmac.digest('hex');

    result += hmacDigest;

    // Base64エンコード
    return Buffer.from(result, 'hex').toString('base64');
}

function authDecrypt(encryptedData, uuid) {
    try {
        // Base64デコード
        const hexData = Buffer.from(encryptedData, 'base64').toString('hex');

        const headerSize = 34; // 2 + 8 + 8 + 16 = 34バイト
        const hmacSize = 32;   // SHA256 = 32バイト

        const encryptedSize = hexData.length / 2 - headerSize - hmacSize;

        if (encryptedSize < 0) {
            throw new Error('無効なデータ形式です');
        }

        // データを分割
        let offset = 0;

        // バージョン情報をスキップ（2バイト）
        offset += 4; // hex文字列なので4文字

        // salt1を取得（8バイト = 16文字）
        const salt1 = Buffer.from(hexData.slice(offset, offset + 16), 'hex');
        offset += 16;

        // salt2を取得（8バイト = 16文字）
        const salt2 = Buffer.from(hexData.slice(offset, offset + 16), 'hex');
        offset += 16;

        // IVを取得（16バイト = 32文字）
        const iv = Buffer.from(hexData.slice(offset, offset + 32), 'hex');
        offset += 32;

        // 暗号化データを取得
        const encrypted = hexData.slice(offset, offset + encryptedSize * 2);

        // HMACを取得
        const receivedHmac = hexData.slice(hexData.length - hmacSize * 2);

        // HMACキーを生成
        const hmacKey = crypto.pbkdf2Sync(uuid, salt2, 10000, 32, 'sha1');

        // HMAC検証
        const hmac = crypto.createHmac('sha256', hmacKey);
        hmac.update(Buffer.from(hexData.slice(0, hexData.length - hmacSize * 2), 'hex'));
        const calculatedHmac = hmac.digest('hex');

        if (calculatedHmac !== receivedHmac) {
            throw new Error('HMAC検証に失敗しました。データが改ざんされている可能性があります');
        }

        // 復号化キーを生成
        const key = crypto.pbkdf2Sync(uuid, salt1, 10000, 32, 'sha1');

        // AES復号化
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        decipher.setAutoPadding(true);

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;

    } catch (error) {
        console.error('復号化エラー:', error);
        return '';
    }
}

export { BitCometApi }