(ns meo.ios.healthkit.common
  (:require [clojure.pprint :as pp]
            [meo.utils.misc :as um]
            [meo.helpers :as h]
            [matthiasn.systems-toolbox.component :as st]))

(def health-kit (js/require "rn-apple-healthkit"))
(def moment (js/require "moment"))

(defn days-ago [n]
  (let [offset (* n 24 60 60 1000)
        date (js/Date. (- (st/now) offset))]
    (.toISOString date)))

(def health-kit-opts
  (clj->js
    {:permissions
     {:read ["Height" "Weight" "StepCount" "BodyMassIndex" "FlightsClimbed"
             "BloodPressureDiastolic" "BloodPressureSystolic" "HeartRate"
             "DistanceWalkingRunning" "SleepAnalysis" "RespiratoryRate"
             "DistanceCycling" "MindfulSession" "ActiveEnergyBurned"
             "BodyFatPercentage" "HeartRateVariability"
             "WalkingHeartRateAverage" "RestingHeartRate"]}}))