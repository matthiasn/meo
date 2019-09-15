(ns meins.electron.main.imap
  "Component for encrypting and decrypting log files."
  (:require [taoensso.timbre :refer-macros [info debug error warn]]
            [meins.electron.main.runtime :as rt]
            [fs :refer [existsSync readFileSync mkdirSync writeFile writeFileSync statSync]]
            [child_process :refer [spawn]]
            [meins.shared.encryption :as mse]
            [meins.electron.main.crypto :as kc]
            [imap :as imap]
            [clojure.data :as data]
            [buildmail :as BuildMail]
            [cljs.reader :as edn]
            [clojure.pprint :as pp]
            [clojure.string :as s]))

(def data-path (:data-path rt/runtime-info))
(def img-path (:img-path rt/runtime-info))
(def audio-path (:audio-path rt/runtime-info))
(def repo-dir (:repo-dir rt/runtime-info))
(def cfg-path (str data-path "/imap.edn"))

(defn pp-str [x]
  (binding [pp/*print-right-margin* 100]
    (with-out-str (pp/pprint x))))

(defn imap-cfg []
  (when (existsSync cfg-path)
    (edn/read-string (readFileSync cfg-path "utf-8"))))

(defn imap-open [mailbox-name open-mb-cb]
  (when-let [cfg (imap-cfg)]
    (try
      (let [conn (imap. (clj->js (:server cfg)))]
        (.once conn "ready" #(do
                               (info "conn ready" mailbox-name)
                               (.openBox conn mailbox-name false (partial open-mb-cb conn))))
        (.once conn "error" #(info "IMAP connection error" %))
        (.once conn "end" #(info "IMAP connection ended:" mailbox-name))
        (.connect conn)
        (js/setTimeout #(.end conn) 120000))
      (catch :default e (error e))))
  {})

(defn buf-from-base64 [b64]
  (.from js/Buffer b64 "base64"))

(defn read-image [mailbox uid partID filename put-fn]
  (info "read-image" mailbox uid partID filename)
  (let [body-cb (fn [buffer seqn stream stream-info]
                  (let [end-cb (fn []
                                 (let [base-64-img (apply str @buffer)
                                       buf (buf-from-base64 base-64-img)
                                       full-path (str img-path "/" filename)
                                       write-cb (fn [err]
                                                  (if err
                                                    (error err)
                                                    (do (info "wrote" full-path)
                                                        (put-fn [:import/gen-thumbs
                                                                 {:filename  filename
                                                                  :full-path full-path}]))))]
                                   (info "image" filename (count base-64-img))
                                   (writeFile full-path buf "binary" write-cb)))]
                    (info "image body stream-info" (js->clj stream-info))
                    (.on stream "data" #(let [s (.toString % "UTF8")]
                                          (when (= partID (.-which stream-info))
                                            (swap! buffer conj s))
                                          (debug "image body data seqno" seqn "- size" (count s))))
                    (.once stream "end" end-cb)))
        msg-cb (fn [msg seqn]
                 (let [buffer (atom [])]
                   (.on msg "body" (partial body-cb buffer seqn))
                   (.once msg "end" #(debug "image msg end" seqn))))
        mb-cb (fn [conn err box]
                (try
                  (let [s (clj->js ["UNDELETED" ["UID" uid]])
                        cb (fn [err res]
                             (let [f (.fetch conn res (clj->js {:bodies [partID]
                                                                :struct true}))
                                   cb (fn []
                                        (info "finished reading" filename)
                                        (.end conn))]
                               (info "search fetch" res)
                               (.on f "message" msg-cb)
                               (.once f "error" #(error "Fetch error" %))
                               (.once f "end" cb)))]
                    (info "search" mailbox s)
                    (.search conn s cb))
                  (catch :default e (do (error e) (.end conn)))))]
    (imap-open mailbox mb-cb)))

(defn read-audio [mailbox uid partID filename put-fn]
  (let [body-cb (fn [buffer seqn stream stream-info]
                  (let [end-cb (fn []
                                 (let [base-64-img (apply str @buffer)
                                       buf (buf-from-base64 base-64-img)
                                       full-path (str audio-path "/" filename)
                                       write-cb (fn [err])]
                                   (info "audio" filename (count base-64-img))
                                   (writeFile full-path buf "binary" write-cb)))]
                    (info "audio body stream-info" (js->clj stream-info))
                    (.on stream "data" #(let [s (.toString % "UTF8")]
                                          (when (= partID (.-which stream-info))
                                            (swap! buffer conj s))
                                          (debug "audio body data seqno" seqn "- size" (count s))))
                    (.once stream "end" end-cb)))
        msg-cb (fn [msg seqn]
                 (let [buffer (atom [])]
                   (.on msg "body" (partial body-cb buffer seqn))
                   (.once msg "end" #(debug "audio msg end" seqn))))
        mb-cb (fn [conn err box]
                (try
                  (let [s (clj->js ["UNDELETED" ["UID" uid]])
                        cb (fn [err res]
                             (let [
                                   f (.fetch conn res (clj->js {:bodies [partID]
                                                                :struct true}))
                                   cb (fn []
                                        (info "finished reading" filename)
                                        (.end conn))]
                               (info "search fetch" res)
                               (.on f "message" msg-cb)
                               (.once f "error" #(error "Fetch error" %))
                               (.once f "end" cb)))]
                    (info "search" mailbox s)
                    (.search conn s cb))
                  (catch :default e (do (error e) (.end conn)))))]
    (imap-open mailbox mb-cb)))

(defn extract-body [s]
  (let [body (-> s
                 (s/replace "=\r\n" "")
                 (s/replace "\r\n" "")
                 (s/replace "\n" ""))]
    (if (s/includes? body "inline")
      (-> body
          (s/split "inline")
          second
          (s/split "--")
          first)
      body)))

(defn read-mailbox [[k mb-cfg] cfg current-state put-fn]
  (let [{:keys [mailbox body-part]} mb-cfg
        their-public-key (some-> cfg :mobile :publicKey mse/hex->array)
        our-private-key (some-> current-state :secretKey mse/hex->array)
        path [:sync :read k :last-read]
        body-cb (fn [buffer seqn stream stream-info]
                  (let [end-cb (fn []
                                 (let [hex-body (extract-body (apply str @buffer))]
                                   (info "end-cb buffer" seqn "- size" (count hex-body))
                                   (debug hex-body)
                                   (when-let [decrypted (mse/decrypt hex-body their-public-key our-private-key)]
                                     (let [msg-type (first decrypted)
                                           {:keys [msg-payload msg-meta]} (second decrypted)
                                           msg-meta (merge msg-meta {:window-id :broadcast})
                                           msg (with-meta [msg-type msg-payload] msg-meta)]
                                       (info "IMAP body end" seqn "- decrypted size" (count (str decrypted)))
                                       (debug msg)
                                       (put-fn msg)))
                                   (info "body-cb last-read" seqn)))]
                    (info "IMAP body stream-info" (js->clj stream-info))
                    (.on stream "data" #(let [s (.toString % "UTF8")]
                                          (when (= body-part (.-which stream-info))
                                            (swap! buffer conj s))
                                          (info "IMAP body data seqno" seqn "- size" (.-size stream-info))))
                    (.once stream "end" end-cb)))
        msg-cb (fn [msg seqn]
                 (let [buffer (atom [])
                       attr-cb (fn [attrs]
                                 (let [uid (.-uid attrs)
                                       struct (js->clj (.-struct attrs) :keywordize-keys true)
                                       attachment (-> struct last last)
                                       filename (some-> attachment
                                                        :disposition
                                                        :params
                                                        :filename
                                                        (s/replace "=?utf-8?Q?" "")
                                                        (s/replace "?=" "")
                                                        (s/replace "=5F" "_"))]
                                   (pp/pprint attachment)
                                   (when (and filename (= "image" (:type attachment)))
                                     (let [partID (:partID attachment)]
                                       (read-image mailbox uid partID filename put-fn)
                                       (info "found attachment" filename uid partID)))
                                   (when (and filename (s/includes? filename "m4a"))
                                     (let [partID (:partID attachment)]
                                       (read-audio mailbox uid partID filename put-fn)
                                       (info "found attachment" filename uid partID)))))]
                   (.once msg "attributes" attr-cb)
                   (.on msg "body" (partial body-cb buffer seqn))
                   (.once msg "end" (fn [] (info "IMAP msg end" seqn)))))
        mb-cb (fn [conn err box]
                (try
                  (let [last-read (:last-read mb-cfg)
                        uid (str (inc last-read) ":*")
                        _ (info "last-read" last-read uid)
                        s (clj->js ["UNDELETED" ["UID" uid]])
                        idle-cb (fn [msg]
                                  (.end conn)
                                  (put-fn
                                    [:schedule/new
                                     {:timeout 100
                                      :message [:sync/read-imap]}]))
                        cb (fn [err res]
                             (let [parsed-res (js->clj res)]
                               (when (and (seq parsed-res) (> (last parsed-res) last-read))
                                 (let [last-read (last parsed-res)
                                       f (.fetch conn res (clj->js {:bodies [body-part]
                                                                    :struct true}))
                                       cb (fn []
                                            (let [cfg (assoc-in (imap-cfg) path last-read)
                                                  s (pp-str cfg)]
                                              (writeFileSync cfg-path s)
                                              (info "mb-cb fetch end, last-read" last-read)
                                              (.on conn "mail" idle-cb)))]
                                   (info "search fetch" res)
                                   (.on f "message" msg-cb)
                                   (.once f "error" #(error "Fetch error" %))
                                   (.once f "end" cb)))))]
                    (info "search" mailbox s)
                    (.search conn s cb))
                  (catch :default e (do (error e) (.end conn)))))]
    (imap-open mailbox mb-cb)))

(defn read-email [{:keys [put-fn current-state]}]
  (let [cfg (imap-cfg)]
    (doseq [mb-tuple (:read (:sync cfg))]
      (read-mailbox mb-tuple cfg current-state put-fn))
    {}))

(defn imap-save [{:keys [ciphertext subject content-type mailbox encoding]}]
  (let [cb (fn [conn _err box]
             (try
               (let [append-cb (fn [err]
                                 (when err
                                   (info "IMAP append error" err))
                                 (info "closing WRITE connection")
                                 (.end conn))
                     cb (fn [_err rfc-2822]
                          (info "RFC2822\n" mailbox rfc-2822)
                          (.append conn rfc-2822 append-cb)
                          (js/console.log (aget conn "_queue")))
                     opts (clj->js {:textEncoding encoding})]
                 (-> (BuildMail. content-type opts)
                     (.setContent ciphertext)
                     (.setHeader "subject" subject)
                     (.build cb)))
               (catch :default e (error e))))]
    (imap-open mailbox cb))
  {})

(defn write-email [{:keys [msg-payload current-state msg-meta]}]
  (when-let [mb-cfg (:write (:sync (imap-cfg)))]
    (try
      (let [mailbox (:mailbox mb-cfg)
            their-public-key (some-> (imap-cfg) :mobile :publicKey mse/hex->array)
            our-private-key (some-> current-state :secretKey mse/hex->array)
            serializable [:entry/sync {:msg-payload msg-payload
                                       :msg-meta    {}}]    ; save battery and bandwidth
            serialized (pr-str serializable)
            subject (str (:timestamp msg-payload))
            cipher-hex (when (and their-public-key our-private-key)
                         (mse/encrypt-asymm serialized their-public-key our-private-key))]
        (when cipher-hex
          (imap-save {:ciphertext   cipher-hex
                      :content-type "text/plain"
                      :encoding     "quoted-printable"
                      :subject      subject
                      :mailbox      mailbox})))
      (catch :default e (error e))))
  {})

(defn read-mb [k d cfg put-fn]
  (try
    (let [cb (fn [conn _err mb]
               (try
                 (.getBoxes conn (fn [err boxes]
                                   (.log js/console boxes)
                                   (put-fn [:imap/status {:status k :detail d}])
                                   (info "read mailboxes")))
                 (catch :default e (put-fn [:imap/status {:status :error :detail (str e)}]))
                 (finally (.end conn))))
          conn (imap. (clj->js (:server cfg)))]
      (.once conn "ready" #(.openBox conn "INBOX" false (partial cb conn)))
      (.once conn "error" #(put-fn [:imap/status {:status :error :detail (str %)}]))
      (.once conn "end" #(info "IMAP connection ended"))
      (.connect conn)
      (js/setTimeout #(.end conn) 120000))
    (catch :default e (put-fn [:imap/status {:status :error :detail (str e)}]))))

(defn read-mailboxes [{:keys [put-fn msg-payload]}]
  (info "read-mailboxes" (update-in msg-payload [:server :password] #(str (subs % 0 2) "...")))
  (when-let [cfg msg-payload]
    (read-mb :read-mailboxes "" cfg put-fn))
  {})

(defn start-sync [{:keys []}]
  (info "starting IMAP sync")
  {:emit-msg [:schedule/new {:timeout 60000
                             :id      :imap-schedule
                             :message [:sync/read-imap]
                             :initial true
                             :repeat  true}]})

(defn get-cfg [{:keys []}]
  {:emit-msg [:imap/cfg (imap-cfg)]})

(defn save-cfg [{:keys [msg-payload put-fn]}]
  (let [s (pp-str msg-payload)]
    (when (read-mb :saved (str "saved: " cfg-path) msg-payload put-fn)
      (writeFileSync cfg-path s)))
  {:emit-msg [[:imap/cfg (imap-cfg)]]})

(defn state-fn [_put-fn]
  (let [state (atom {})]
    (-> (kc/get-secret-key)
        (.then #(swap! state assoc :secretKey %)))
    (-> (kc/get-public-key)
        (.then #(swap! state assoc :publicKey %)))
    {:state state}))

(defn cmp-map [cmp-id]
  {:cmp-id      cmp-id
   :state-fn    state-fn
   :opts        {:in-chan  [:buffer 100]
                 :out-chan [:buffer 100]}
   :handler-map {:sync/imap       write-email
                 :imap/get-status read-mailboxes
                 :imap/get-cfg    get-cfg
                 :imap/save-cfg   save-cfg
                 :sync/start-imap start-sync
                 :sync/read-imap  read-email}})
