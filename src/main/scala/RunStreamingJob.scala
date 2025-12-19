import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions._
import org.apache.spark.sql.types.{DoubleType, StringType, StructType}
import org.apache.spark.ml.PipelineModel
import org.apache.spark.sql.streaming.Trigger
import org.apache.spark.sql.DataFrame
import java.io.File

object RunStreamingJob {
  def main(args: Array[String]): Unit = {

    val spark = SparkSession.builder
      .appName("LogAnomalyStreamProcessor-GBT")
      .master("local[*]")
      .getOrCreate()

    spark.sparkContext.setLogLevel("WARN")
    println("Loading High-Tech GBT Model...")

    val OUTPUT_DIR = "output_alerts"
    val STATUS_FILE = "_STATUS_DONE.txt"
    val model = PipelineModel.load("my_gbt_model")

    // Check your training log. Usually 1.0 for GBT anomalies.
    val ANOMALY_PREDICTION_ID = 0.0

    val schema = new StructType()
      .add(" Flow Duration", StringType)
      .add(" Flow IAT Mean", StringType)
      .add(" Total Fwd Packets", StringType)
      .add(" Total Backward Packets", StringType)
      .add(" Fwd Packet Length Mean", StringType)
      .add(" Bwd Packet Length Mean", StringType)
      .add(" Label", StringType)

    println(s"Waiting for CSV files in 'input_logs' directory...")

    val logStreamDF = spark.readStream
      .option("header", "true")
      .schema(schema)
      .csv("input_logs")

    val featuresStreamDF = logStreamDF
      .withColumn("fwd_packets", trim(col(" Total Fwd Packets")).cast(DoubleType))
      .withColumn("bwd_packets", trim(col(" Total Backward Packets")).cast(DoubleType))
      .withColumn("flow_iat_mean", trim(col(" Flow IAT Mean")).cast(DoubleType))
      .withColumn("fwd_pkt_len_mean", trim(col(" Fwd Packet Length Mean")).cast(DoubleType))
      .withColumn("bwd_pkt_len_mean", trim(col(" Bwd Packet Length Mean")).cast(DoubleType))
      .na.drop()

    val predictionsStreamDF = model.transform(featuresStreamDF)

    val anomalyStreamDF = predictionsStreamDF
      .filter(col("prediction") === ANOMALY_PREDICTION_ID)
      .select("fwd_packets", "bwd_packets", "flow_iat_mean", "fwd_pkt_len_mean", "bwd_pkt_len_mean", "prediction")

    val query = anomalyStreamDF.writeStream
      .outputMode("append")
      .trigger(Trigger.ProcessingTime("15 seconds"))
      .option("checkpointLocation", "spark_checkpoint_gbt")
      .foreachBatch { (batchDF: DataFrame, batchId: Long) =>
        println(s"Processing batch $batchId...")

        // Create output dir if missing
        new File(OUTPUT_DIR).mkdirs()

        if (!batchDF.isEmpty) {
          println(s"*** THREAT DETECTED IN BATCH $batchId ***")
          batchDF.coalesce(1)
            .write
            .format("csv")
            .option("header", "true")
            .mode("append")
            .save(OUTPUT_DIR)
        }

        // Create status file for UI
        val file = new File(s"$OUTPUT_DIR/$STATUS_FILE")
        file.createNewFile()

        // --- THE FIX IS HERE ---
        () // Explicitly return Unit (void) to satisfy Scala compiler
      }
      .start()

    query.awaitTermination()
  }
}