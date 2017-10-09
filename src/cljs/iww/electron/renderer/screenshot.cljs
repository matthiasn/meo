(ns iww.electron.renderer.screenshot
  (:require [taoensso.timbre :as timbre :refer-macros [info debug]]
            [iww.electron.renderer.helpers :as h]
            [matthiasn.systems-toolbox.component :as st]))

(defn state-fn [put-fn]
  (let [observed (atom {})]
    {:observed observed}))

(defn screenshot [{:keys [observed current-state put-fn msg-payload]}]
  (let [cfg (:cfg @observed)
        screenshot-ts (st/now)
        filename (str screenshot-ts ".png")
        entry (merge {:img-file filename} msg-payload)
        new-fn (h/new-entry-fn put-fn entry nil)]
    (js/setTimeout new-fn 1000)
    (when-not (:app-screenshot cfg)
      (put-fn [:window/hide])
      (put-fn [:cmd/schedule-new {:message [:window/show] :timeout 1200}]))
    {:emit-msg [:cmd/schedule-new
                {:message [:import/screenshot {:filename filename}]
                 :timeout 500}]}))

(defn cmp-map [cmp-id]
  {:cmp-id      cmp-id
   :state-fn    state-fn
   :handler-map {:screenshot/take screenshot}})

