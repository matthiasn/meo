(ns meins.components.sync
  (:require-macros [cljs.core.async.macros :refer [go]])
  (:require [glittershark.core-async-storage :as as]
            [cljs.core.async :refer [<!]]
            [meins.ui.shared :as shared :refer [platform-os]]
            [meins.shared.encryption :as mse]
            [re-frame.core :refer [subscribe]]
            ["@matthiasn/react-native-mailcore" :default MailCore]
            ["@react-native-community/netinfo" :as net-info]
            [meins.ui.db :as uidb]
            [cljs.reader :as edn]
            [clojure.string :as str]
            [meins.util.keychain :as kc]))

(defn extract-body [s]
  (-> (str s)
      (str/split "-")
      first
      (str/replace " " "")
      (str/replace "=\r\n" "")
      (str/replace "\r\n" "")
      (str/replace "\n" "")))

(defn sync-write [{:keys [msg-type msg-payload put-fn cmp-state db-item]}]
  (when-let [secrets (:secrets @cmp-state)]
    (try
      (when (:online @cmp-state)
        (let [their-public-key (-> secrets :desktop :publicKey mse/hex->array)
              my-private-key (-> @cmp-state :key-pair :secretKey mse/hex->array)
              folder (-> secrets :sync :write :folder)
              update-filename (fn [entry]
                                (if (:img_file entry)
                                  (update entry :img_file #(str/replace % ".PNG" ".JPG"))
                                  entry))
              serializable [msg-type {:msg-payload (update-filename msg-payload)
                                      :msg-meta    {}}]     ; save battery and bandwidth
              serialized (pr-str serializable)
              hex-cipher (mse/encrypt-asymm serialized their-public-key my-private-key)
              photo-uri (-> msg-payload :media :image :uri)
              filename (:img_file msg-payload)
              audiofile (:audio_file msg-payload)
              mb (-> secrets :server :username)
              mail (merge (:server secrets)
                          {:folder   folder
                           :from     {:addressWithDisplayName mb
                                      :mailbox                mb}
                           :to       {:addressWithDisplayName mb
                                      :mailbox                mb}
                           :subject  (str (:timestamp msg-payload))
                           :textBody hex-cipher}
                          (when audiofile {:audiofile audiofile})
                          (when (and (= "android" platform-os) audiofile)
                            {:audiopath (str "/data/data/com.matthiasn.meins/" audiofile)})
                          (when (and (= :entry/sync msg-type) filename)
                            {:attachmentUri photo-uri
                             :filename      filename}))
              success-cb (fn []
                           (when db-item
                             (.write @uidb/realm-db #(set! (.-sync db-item) "DONE"))
                             (put-fn [:schedule/new {:timeout 100
                                                     :message [:sync/retry]
                                                     :id      :sync}])))
              error-cb (fn [err]
                         (when db-item
                           (.write @uidb/realm-db #(set! (.-sync db-item) "ERROR"))
                           (js/console.error (str (js->clj err)))
                           (put-fn [:schedule/new {:timeout 100
                                                   :message [:sync/retry]
                                                   :id      :sync}])))]
          (swap! cmp-state update-in [:open-writes] conj msg-payload)
          (.write @uidb/realm-db #(set! (.-sync db-item) "STARTED"))
          (-> (.saveImap MailCore (clj->js mail))
              (.then success-cb)
              (.catch error-cb))))
      (catch :default e (js/console.error (str e)))))
  {})

(defn schedule-read [cmp-state put-fn]
  (when (seq (:not-fetched @cmp-state))
    (put-fn [:schedule/new
             {:timeout 1000
              :message [:sync/read]}])))

(defn sync-get-uids [{:keys [put-fn cmp-state current-state]}]
  (when-let [secrets (:secrets @cmp-state)]
    (when (:online current-state)
      (try
        (when (= platform-os "ios")
          (let [folder (-> secrets :sync :read :folder)
                min-uid (or (last (:not-fetched current-state))
                            (inc (:last-uid-read current-state)))
                mail (merge (:server secrets)
                            {:folder folder
                             :minUid min-uid
                             :length 1000})
                fetch-cb (fn [data]
                           (let [uids (edn/read-string (str "[" data "]"))]
                             (swap! cmp-state update :not-fetched into uids)
                             (schedule-read cmp-state put-fn)))]
            (-> (.fetchImap MailCore (clj->js mail))
                (.then fetch-cb)
                (.catch #(shared/alert (str %))))))
        (catch :default e (shared/alert (str e))))))
  {})

(defn sync-read-msg [{:keys [put-fn cmp-state current-state]}]
  (when-let [secrets (:secrets current-state)]
    (try
      (when (and (:online current-state) (= platform-os "ios"))
        (let [{:keys [fetched not-fetched]} @cmp-state
              their-public-key (-> secrets :desktop :publicKey mse/hex->array)
              our-private-key (-> @cmp-state :key-pair :secretKey mse/hex->array)
              not-fetched (drop-while #(contains? fetched %) not-fetched)]
          (doseq [uid not-fetched]
            (let [folder (-> secrets :sync :read :folder)
                  mail (merge (:server secrets)
                              {:folder folder
                               :uid    uid})
                  fetch-cb (fn [data]
                             (schedule-read cmp-state put-fn)
                             (let [body (get (js->clj data) "body")
                                   decrypted (time (mse/decrypt body their-public-key our-private-key))
                                   msg-type (first decrypted)
                                   {:keys [msg-payload msg-meta]} (second decrypted)
                                   msg (with-meta [msg-type msg-payload]
                                                  (assoc msg-meta :from-sync true))]
                               (swap! cmp-state assoc-in [:last-uid-read] uid)
                               (go (<! (as/set-item :last-uid-read uid)))
                               (swap! cmp-state update-in [:not-fetched] disj uid)
                               (swap! cmp-state update-in [:fetched] conj uid)
                               (put-fn msg)))]
              (-> (.fetchImapByUid MailCore (clj->js mail))
                  (.then fetch-cb)
                  (.catch #(.log js/console (str (js->clj %)))))))))
      (catch :default e (js/console.error (str e)))))
  {})

(defn retry-write [{:keys [cmp-state current-state put-fn]}]
  (let [cfg (subscribe [:cfg])
        res (some-> @uidb/realm-db
                    (.objects "Entry")
                    (.filtered "sync == \"OPEN\"")
                    (.slice 0 1))]
    (when (and (:online current-state) (:sync-active @cfg))
      (doseq [x res]
        (sync-write {:db-item     x
                     :cmp-state   cmp-state
                     :put-fn      put-fn
                     :msg-type    :entry/sync
                     :msg-payload (edn/read-string (aget x "edn"))}))))
  {})

(defn set-secrets [{:keys [current-state msg-payload]}]
  (let [new-state (assoc-in current-state [:secrets] msg-payload)]
    (go (<! (as/set-item :secrets msg-payload)))
    {:new-state new-state}))

(defn state-fn [put-fn]
  (let [state (atom {:last-uid-read 1
                     :not-fetched   (sorted-set)
                     :open-writes   #{}
                     :fetched       #{}
                     :online        false})
        listener (fn [ev]
                   (swap! state assoc :online (.-isInternetReachable ev)))]
    (.addEventListener net-info listener)
    (kc/get-keypair #(swap! state assoc :key-pair %))
    (go (try
          (let [secrets (second (<! (as/get-item :secrets)))]
            (when secrets
              (swap! state assoc-in [:secrets] secrets)))
          (catch js/Object e
            (put-fn [:debug/error {:msg e}]))))
    (go (try
          (let [uid (second (<! (as/get-item :last-uid-read)))]
            (when uid
              (swap! state assoc-in [:last-uid-read] uid)))
          (catch js/Object e
            (put-fn [:debug/error {:msg e}]))))
    {:state state}))

(defn cmp-map [cmp-id]
  {:cmp-id      cmp-id
   :state-fn    state-fn
   :handler-map {:entry/sync  sync-write
                 :sync/fetch  sync-get-uids
                 :sync/retry  retry-write
                 :sync/read   sync-read-msg
                 :secrets/set set-secrets}})